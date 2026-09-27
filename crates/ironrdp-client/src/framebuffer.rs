//! A framebuffer the session updates in place and the host presents from.
//!
//! [`RdpOutputEvent::Image`] carries a freshly converted copy of the whole desktop for every
//! graphics update: at 2560x1440 that is 15 MB converted, allocated and copied even when only
//! a caret blinked. A [`SharedFramebuffer`] handed to [`RdpClient::with_shared_framebuffer`]
//! is instead converted in place for the region each update names, and the host repaints
//! only the area returned by [`Framebuffer::take_dirty`].
//!
//! [`RdpOutputEvent::Image`]: crate::rdp::RdpOutputEvent::Image
//! [`RdpClient::with_shared_framebuffer`]: crate::rdp::RdpClient::with_shared_framebuffer

use core::num::NonZeroU16;
use core::time::Duration;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use ironrdp_pdu::geometry::{InclusiveRectangle, Rectangle as _};

/// The remote desktop as `0x00RRGGBB` pixels, row-major with a stride of [`Self::width`]:
/// the layout of [`RdpOutputEvent::Image`](crate::rdp::RdpOutputEvent::Image).
#[derive(Debug, Default)]
pub struct Framebuffer {
    pixels: Vec<u32>,
    width: u16,
    height: u16,
    /// Bounding box of every area changed since the host last took it.
    dirty: Option<InclusiveRectangle>,
    /// The next update converts the whole image rather than only its region.
    stale: bool,
    /// Time the host reported spending on presenting since the session last read it.
    present_time: Duration,
}

impl Framebuffer {
    /// Width in pixels; zero until the first frame.
    pub fn width(&self) -> u16 {
        self.width
    }

    /// Height in pixels; zero until the first frame.
    pub fn height(&self) -> u16 {
        self.height
    }

    /// `width * height` pixels in `0x00RRGGBB` form.
    pub fn pixels(&self) -> &[u32] {
        &self.pixels
    }

    /// Takes the bounding box of the areas changed since the last call, if any.
    ///
    /// It always lies within the current [`Self::width`] x [`Self::height`].
    #[must_use = "the returned region must be painted before its damage is discarded"]
    pub fn take_dirty(&mut self) -> Option<InclusiveRectangle> {
        self.dirty.take()
    }

    /// Converts `region` of an RGBA32 image into the frame and adds it to the dirty area.
    ///
    /// The whole image is converted instead when its size differs from the frame's (the first
    /// frame, a resize) or after [`Self::invalidate`]. A region reaching outside the image is
    /// clipped to it.
    ///
    /// Returns `true` when this update adds damage to a frame that had none. The host needs
    /// a notification then; later updates merge into the area it has yet to take.
    ///
    /// # Panics
    ///
    /// Panics if `rgba` does not hold exactly `width * height` four-byte pixels.
    pub fn update(&mut self, rgba: &[u8], width: u16, height: u16, region: &InclusiveRectangle) -> bool {
        assert_eq!(
            rgba.len(),
            usize::from(width) * usize::from(height) * 4,
            "image data does not match its size"
        );
        let (Some(right), Some(bottom)) = (width.checked_sub(1), height.checked_sub(1)) else {
            return false;
        };
        let whole = InclusiveRectangle {
            left: 0,
            top: 0,
            right,
            bottom,
        };

        let needs_notification = self.dirty.is_none();
        let region = if self.stale || (width, height) != (self.width, self.height) {
            self.stale = false;
            self.width = width;
            self.height = height;
            self.pixels.resize(usize::from(width) * usize::from(height), 0);
            // The previous dirty area may lie outside the new size, and all of the frame changes anyway.
            self.dirty = None;
            whole
        } else {
            let Some(region) = region.intersect(&whole) else {
                return false;
            };
            region
        };

        let stride = usize::from(width);
        let (left, right) = (usize::from(region.left), usize::from(region.right) + 1);
        for y in usize::from(region.top)..=usize::from(region.bottom) {
            let row = y * stride;
            let source = &rgba[(row + left) * 4..(row + right) * 4];
            let target = &mut self.pixels[row + left..row + right];
            for (output_pixel, pixel) in target.iter_mut().zip(source.chunks_exact(4)) {
                *output_pixel = u32::from_be_bytes([0, pixel[0], pixel[1], pixel[2]]);
            }
        }

        self.dirty = Some(match self.dirty.take() {
            Some(pending) => pending.union(&region),
            None => region,
        });
        needs_notification
    }

    /// Replaces the whole frame, for hosts that also receive full frames such as
    /// [`RdpOutputEvent::Image`](crate::rdp::RdpOutputEvent::Image).
    ///
    /// Returns `true` when the frame had no pending dirty area before, as [`Self::update`] does.
    /// The next [`Self::update`] converts its whole image, since the frame no longer mirrors it.
    ///
    /// # Panics
    ///
    /// Panics if `pixels` does not hold exactly `width * height` pixels.
    pub fn replace(&mut self, pixels: Vec<u32>, width: NonZeroU16, height: NonZeroU16) -> bool {
        assert_eq!(
            pixels.len(),
            usize::from(width.get()) * usize::from(height.get()),
            "frame data does not match its size"
        );
        let needs_notification = self.dirty.is_none();
        self.pixels = pixels;
        self.width = width.get();
        self.height = height.get();
        self.stale = true;
        self.dirty = Some(InclusiveRectangle {
            left: 0,
            top: 0,
            right: width.get() - 1,
            bottom: height.get() - 1,
        });
        needs_notification
    }

    /// Makes the next [`Self::update`] convert the whole image: the image it mirrors was
    /// replaced (a new connection, a reactivation) and may no longer match the frame outside
    /// the regions still to come.
    pub fn invalidate(&mut self) {
        self.stale = true;
    }

    /// Adds `elapsed` to the presenting time reported in the session's `session perf` log.
    pub fn record_present(&mut self, elapsed: Duration) {
        self.present_time += elapsed;
    }

    pub(crate) fn take_present_time(&mut self) -> Duration {
        core::mem::take(&mut self.present_time)
    }
}

/// A [`Framebuffer`] shared between the session, which writes it, and the host, which presents it.
#[derive(Clone, Debug, Default)]
pub struct SharedFramebuffer(Arc<Mutex<Framebuffer>>);

impl SharedFramebuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Locks the frame. Hold the guard only for as long as it takes to copy pixels in or out:
    /// the session waits on it before it can apply the next update.
    pub fn lock(&self) -> MutexGuard<'_, Framebuffer> {
        // A panic while the lock was held can at worst leave some pixels of a region
        // unconverted, which the next update of that region repairs.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}
