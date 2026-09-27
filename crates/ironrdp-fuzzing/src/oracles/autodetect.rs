use arbitrary::Unstructured;
use ironrdp_autodetect::AutoDetectState;
use ironrdp_core::{MonotonicInstant, decode, encode_vec};
use ironrdp_pdu::rdp::autodetect::{AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu};

/// Exercises request ordering, absent/regressing timestamps, and counter saturation.
pub fn autodetect_state(data: &[u8]) {
    let mut input = Unstructured::new(data);
    let mut state = AutoDetectState::default();
    while !input.is_empty() {
        let Ok((operation, millis, byte_count)) = input.arbitrary::<(u8, u64, u32)>() else {
            break;
        };
        let sequence = u16::from(operation);
        let request = match operation % 7 {
            0 => AutoDetectRequest::bw_start_continuous(sequence),
            1 => AutoDetectRequest::bw_stop_continuous(sequence),
            2 => AutoDetectRequest::bw_start_connect_time(sequence),
            3 => AutoDetectRequest::bw_stop_connect_time(sequence, vec![0; usize::from(operation) + 1]),
            4 => AutoDetectRequest::bw_payload(sequence, vec![0; usize::from(operation)]),
            5 => AutoDetectRequest::rtt_continuous(sequence),
            _ => AutoDetectRequest::netchar_result(sequence, 0, byte_count, 0),
        };
        state.record_data(usize::try_from(byte_count).unwrap_or(usize::MAX));
        let received_at = (operation & 0x80 == 0).then(|| MonotonicInstant::from_millis(millis));
        if let Some(response) = state.process_request(&request, received_at) {
            if let AutoDetectResponse::BandwidthMeasureResults { time_delta_ms, .. } = &response {
                assert_ne!(*time_delta_ms, 0);
            }
            let pdu = AutoDetectRspPdu::new(response);
            let wire = encode_vec(&pdu).expect("auto-detect response must encode");
            assert_eq!(decode::<AutoDetectRspPdu>(&wire).expect("response must decode"), pdu);
        }
    }
}
