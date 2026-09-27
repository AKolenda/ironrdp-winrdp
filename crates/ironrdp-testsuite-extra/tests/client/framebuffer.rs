use core::num::NonZeroU16;

use ironrdp_client::framebuffer::Framebuffer;
use ironrdp_client::output_channel::output_channel;
use ironrdp_client::rdp::RdpOutputEvent;
use ironrdp_pdu::geometry::InclusiveRectangle;

fn rectangle(left: u16, top: u16, right: u16, bottom: u16) -> InclusiveRectangle {
    InclusiveRectangle {
        left,
        top,
        right,
        bottom,
    }
}

fn rgba(pixels: &[u32]) -> Vec<u8> {
    pixels
        .iter()
        .flat_map(|pixel| {
            let [_, red, green, blue] = pixel.to_be_bytes();
            [red, green, blue, 255]
        })
        .collect()
}

#[test]
fn the_first_update_initializes_the_whole_desktop() {
    let mut frame = Framebuffer::default();
    let pixels = [0x12_34_56, 0x78_9A_BC, 0xDE_F0_12, 0x34_56_78];

    assert!(frame.update(&rgba(&pixels), 2, 2, &rectangle(1, 1, 1, 1)));
    assert_eq!((frame.width(), frame.height()), (2, 2));
    assert_eq!(frame.pixels(), pixels);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 1, 1)));
    assert_eq!(frame.take_dirty(), None);
}

#[test]
fn later_updates_convert_only_the_named_pixels_and_union_pending_damage() {
    let mut frame = Framebuffer::default();
    frame.update(&rgba(&[1, 2, 3, 4, 5, 6]), 3, 2, &rectangle(0, 0, 2, 1));
    let _ = frame.take_dirty();

    let updated = rgba(&[10, 20, 30, 40, 50, 60]);
    assert!(frame.update(&updated, 3, 2, &rectangle(2, 0, 2, 0)));
    assert!(!frame.update(&updated, 3, 2, &rectangle(0, 1, 0, 1)));
    assert_eq!(frame.pixels(), [1, 2, 30, 40, 5, 6]);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 2, 1)));
}

#[test]
fn updates_are_clipped_and_empty_regions_do_not_notify() {
    let mut frame = Framebuffer::default();
    frame.update(&rgba(&[1, 2, 3, 4]), 2, 2, &rectangle(0, 0, 1, 1));
    let _ = frame.take_dirty();

    let updated = rgba(&[10, 20, 30, 40]);
    assert!(!frame.update(&updated, 2, 2, &rectangle(2, 0, 3, 1)));
    assert!(!frame.update(&updated, 2, 2, &rectangle(1, 0, 0, 1)));
    assert_eq!(frame.take_dirty(), None);
    assert!(frame.update(&updated, 2, 2, &rectangle(1, 1, u16::MAX, u16::MAX)));
    assert_eq!(frame.pixels(), [1, 2, 3, 40]);
    assert_eq!(frame.take_dirty(), Some(rectangle(1, 1, 1, 1)));
}

#[test]
fn resize_replaces_pixels_and_pending_damage_without_a_second_notification() {
    let mut frame = Framebuffer::default();
    assert!(frame.update(&rgba(&[1, 2, 3, 4]), 2, 2, &rectangle(0, 0, 1, 1)));
    assert!(!frame.update(&rgba(&[5, 6, 7]), 3, 1, &rectangle(2, 0, 2, 0)));

    assert_eq!((frame.width(), frame.height()), (3, 1));
    assert_eq!(frame.pixels(), [5, 6, 7]);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 2, 0)));
}

#[test]
fn reactivation_refreshes_unchanged_regions_at_the_same_size() {
    let mut frame = Framebuffer::default();
    frame.update(&rgba(&[1, 2, 3, 4]), 2, 2, &rectangle(0, 0, 1, 1));
    let _ = frame.take_dirty();
    frame.invalidate();

    assert!(frame.update(&rgba(&[5, 6, 7, 8]), 2, 2, &rectangle(1, 1, 1, 1)));
    assert_eq!(frame.pixels(), [5, 6, 7, 8]);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 1, 1)));
}

#[test]
fn full_frame_replacement_preserves_notification_state_and_invalidates_conversion() {
    let mut frame = Framebuffer::default();
    let width = NonZeroU16::new(2).unwrap();
    let height = NonZeroU16::new(1).unwrap();

    assert!(frame.replace(vec![1, 2], width, height));
    assert!(!frame.replace(vec![3, 4], width, height));
    assert_eq!(frame.pixels(), [3, 4]);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 1, 0)));

    assert!(frame.update(&rgba(&[5, 6]), 2, 1, &rectangle(1, 0, 1, 0)));
    assert_eq!(frame.pixels(), [5, 6]);
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 1, 0)));
}

#[tokio::test]
async fn updates_after_notification_delivery_remain_pending_until_painted() {
    let (sender, mut receiver) = output_channel(1);
    let mut frame = Framebuffer::default();
    frame.update(&rgba(&[1, 2, 3]), 3, 1, &rectangle(0, 0, 2, 0));
    let _ = frame.take_dirty();

    assert!(frame.update(&rgba(&[10, 2, 3]), 3, 1, &rectangle(0, 0, 0, 0)));
    sender.try_send(RdpOutputEvent::FramebufferUpdated).unwrap();
    assert!(matches!(
        receiver.recv().await,
        Some(RdpOutputEvent::FramebufferUpdated)
    ));

    // The UI event was delivered, but drawing has not acquired the frame yet.
    assert!(!frame.update(&rgba(&[10, 2, 30]), 3, 1, &rectangle(2, 0, 2, 0)));
    assert_eq!(frame.take_dirty(), Some(rectangle(0, 0, 2, 0)));
    assert_eq!(frame.pixels(), [10, 2, 30]);

    // Once drawing consumes the accumulated damage, the next update wakes it again.
    assert!(frame.update(&rgba(&[10, 20, 30]), 3, 1, &rectangle(1, 0, 1, 0)));
    sender.try_send(RdpOutputEvent::FramebufferUpdated).unwrap();
    drop(sender);
    assert!(matches!(
        receiver.recv().await,
        Some(RdpOutputEvent::FramebufferUpdated)
    ));
    assert!(receiver.recv().await.is_none());
    assert_eq!(frame.take_dirty(), Some(rectangle(1, 0, 1, 0)));
}
