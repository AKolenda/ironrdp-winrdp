#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(doc, doc = include_str!("../README.md"))]

use ironrdp_core::MonotonicInstant;
use ironrdp_pdu::rdp::autodetect::{
    AutoDetectRequest, AutoDetectResponse, BW_RESULTS_CONNECT_TIME, BW_RESULTS_CONTINUOUS, BW_START_CONNECT_TIME,
    BW_START_RELIABLE_UDP, BW_STOP_CONNECT_TIME, BW_STOP_RELIABLE_UDP,
};

/// Size of the Payload and connect-time Stop headers, excluding the Security Header.
const PAYLOAD_HEADER_SIZE: u32 = 1 /* headerLength */
    + 1 /* headerTypeId */
    + 2 /* sequenceNumber */
    + 2 /* requestType */
    + 2 /* payloadLength */;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MeasurementKind {
    ConnectTime,
    Continuous,
}

#[derive(Debug, Clone)]
struct BandwidthMeasurement {
    kind: MeasurementKind,
    started_at: MonotonicInstant,
    byte_count: u32,
}

/// Client-side network detection on the main RDP connection ([MS-RDPBCGR 3.2.5.14]).
///
/// Keep one instance for the lifetime of the connection, moving it between the
/// session and activation state machines as needed. Timestamps must come from the
/// same driver-owned monotonic clock throughout that lifetime.
///
/// [MS-RDPBCGR 3.2.5.14]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/16ffa852-8aa7-481c-99a0-36c1a9a198f6
#[derive(Debug, Clone, Default)]
pub struct AutoDetectState {
    bandwidth: Option<BandwidthMeasurement>,
}

impl AutoDetectState {
    /// Counts an incoming PDU during continuous detection.
    ///
    /// Call once per PDU before [`Self::process_request`], excluding transport and
    /// security headers. Connect-time payloads are counted by `process_request`.
    pub fn record_data(&mut self, byte_count: usize) {
        if let Some(measurement) = &mut self.bandwidth
            && measurement.kind == MeasurementKind::Continuous
        {
            measurement.byte_count = measurement.byte_count.saturating_add(saturating_byte_count(byte_count));
        }
    }

    /// Processes a main-channel request and returns its response, when required.
    ///
    /// Starts reset the current measurement; Stops close only a matching kind.
    /// A missing timestamp discards accumulated bytes rather than reporting them
    /// against an invented interval. Replies use a one-millisecond floor, with
    /// only the connect-time Stop's own bytes when no measurement is available.
    /// Lossy tunnel requests and informational network results produce no reply.
    pub fn process_request(
        &mut self,
        request: &AutoDetectRequest,
        received_at: Option<MonotonicInstant>,
    ) -> Option<AutoDetectResponse> {
        match request {
            AutoDetectRequest::RttRequest { sequence_number, .. } => Some(AutoDetectResponse::RttResponse {
                sequence_number: *sequence_number,
            }),
            AutoDetectRequest::BandwidthMeasureStart { request_type, .. } => {
                let kind = match *request_type {
                    BW_START_CONNECT_TIME => MeasurementKind::ConnectTime,
                    BW_START_RELIABLE_UDP => MeasurementKind::Continuous,
                    _ => return None,
                };
                self.bandwidth = received_at.map(|started_at| BandwidthMeasurement {
                    kind,
                    started_at,
                    byte_count: 0,
                });
                None
            }
            AutoDetectRequest::BandwidthMeasurePayload { payload, .. } => {
                if let Some(measurement) = &mut self.bandwidth
                    && measurement.kind == MeasurementKind::ConnectTime
                {
                    measurement.byte_count = measurement.byte_count.saturating_add(payload_byte_count(payload.len()));
                }
                None
            }
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number,
                request_type,
                payload,
            } => {
                let (kind, response_type, stop_bytes) = match *request_type {
                    BW_STOP_CONNECT_TIME => (
                        MeasurementKind::ConnectTime,
                        BW_RESULTS_CONNECT_TIME,
                        payload.as_ref().map_or(0, |payload| payload_byte_count(payload.len())),
                    ),
                    BW_STOP_RELIABLE_UDP => (MeasurementKind::Continuous, BW_RESULTS_CONTINUOUS, 0),
                    _ => return None,
                };
                let measurement = if self
                    .bandwidth
                    .as_ref()
                    .is_some_and(|measurement| measurement.kind == kind)
                {
                    self.bandwidth.take()
                } else {
                    None
                };
                let (time_delta_ms, byte_count) = match (measurement, received_at) {
                    (Some(measurement), Some(stopped_at)) => (
                        u32::try_from(stopped_at.duration_since(measurement.started_at).as_millis())
                            .unwrap_or(u32::MAX)
                            .max(1),
                        measurement.byte_count.saturating_add(stop_bytes),
                    ),
                    _ => (1, stop_bytes),
                };
                Some(AutoDetectResponse::BandwidthMeasureResults {
                    sequence_number: *sequence_number,
                    response_type,
                    time_delta_ms,
                    byte_count,
                })
            }
            AutoDetectRequest::NetworkCharacteristicsResult { .. } => None,
        }
    }
}

fn saturating_byte_count(byte_count: usize) -> u32 {
    u32::try_from(byte_count).unwrap_or(u32::MAX)
}

fn payload_byte_count(payload_len: usize) -> u32 {
    saturating_byte_count(payload_len).saturating_add(PAYLOAD_HEADER_SIZE)
}
