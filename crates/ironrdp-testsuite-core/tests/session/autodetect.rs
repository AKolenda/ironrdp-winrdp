use std::borrow::Cow;

use ironrdp_core::encode_vec;
use ironrdp_pdu::mcs::{McsMessage, SendDataIndication};
use ironrdp_pdu::rdp::autodetect::{AutoDetectReqPdu, AutoDetectRequest, AutoDetectResponse, AutoDetectRspPdu};
use ironrdp_pdu::x224::X224;
use ironrdp_session::x224::Processor;
use ironrdp_svc::StaticChannelSet;

const USER_CHANNEL_ID: u16 = 1002;
const IO_CHANNEL_ID: u16 = 1003;
const MESSAGE_CHANNEL_ID: u16 = 1004;
const SHARE_ID: u32 = 0x0001_0000;

fn make_processor() -> Processor {
    Processor::new(
        StaticChannelSet::new(),
        USER_CHANNEL_ID,
        IO_CHANNEL_ID,
        Some(MESSAGE_CHANNEL_ID),
        SHARE_ID,
    )
}

fn process_frame(processor: &mut Processor, frame: &[u8]) -> Vec<ironrdp_session::x224::ProcessorOutput> {
    let mut bulk_decompressor = None;
    processor.process(frame, &mut bulk_decompressor).expect("process frame")
}

/// Encode an Auto-Detect Request as a server-to-client SendDataIndication on the
/// MCS message channel ([MS-RDPBCGR] 2.2.14.3): the auto-detect data is framed by
/// a Basic Security Header (SEC_AUTODETECT_REQ), not a Share Data header.
fn encode_server_autodetect(request: AutoDetectRequest) -> Vec<u8> {
    let pdu = AutoDetectReqPdu::new(request);
    let user_data = encode_vec(&pdu).unwrap();

    let indication = McsMessage::SendDataIndication(SendDataIndication {
        initiator_id: USER_CHANNEL_ID,
        channel_id: MESSAGE_CHANNEL_ID,
        user_data: Cow::Owned(user_data),
    });

    encode_vec(&X224(indication)).unwrap()
}

#[test]
fn rtt_request_produces_response_frame() {
    let mut processor = make_processor();
    let request = AutoDetectRequest::rtt_continuous(42);
    let frame = encode_server_autodetect(request);

    let outputs = process_frame(&mut processor, &frame);

    assert_eq!(outputs.len(), 1);
    match &outputs[0] {
        ironrdp_session::x224::ProcessorOutput::ResponseFrame(data) => {
            assert!(!data.is_empty(), "response frame must not be empty");
        }
        other => panic!("expected ResponseFrame, got {other:?}"),
    }
}

#[test]
fn rtt_response_preserves_sequence_number() {
    let mut processor = make_processor();
    let sequence_number = 0x1234;
    let request = AutoDetectRequest::rtt_connect_time(sequence_number);
    let frame = encode_server_autodetect(request);

    let outputs = process_frame(&mut processor, &frame);

    assert_eq!(outputs.len(), 1);
    let ironrdp_session::x224::ProcessorOutput::ResponseFrame(response_data) = &outputs[0] else {
        panic!("expected ResponseFrame");
    };

    // The response is a Client Auto-Detect Response PDU on the message channel:
    // X224 > MCS SendDataRequest > BasicSecurityHeader(SEC_AUTODETECT_RSP) > data.
    let mcs_msg = ironrdp_core::decode::<X224<McsMessage<'_>>>(response_data).unwrap();
    let McsMessage::SendDataRequest(send_data) = mcs_msg.0 else {
        panic!("expected SendDataRequest in response frame");
    };
    assert_eq!(
        send_data.channel_id, MESSAGE_CHANNEL_ID,
        "response must be sent on the message channel"
    );

    let response = ironrdp_core::decode::<AutoDetectRspPdu>(&send_data.user_data).unwrap();
    match response.response {
        AutoDetectResponse::RttResponse {
            sequence_number: rsp_seq,
        } => {
            assert_eq!(rsp_seq, sequence_number, "sequence number must be echoed");
        }
        other => panic!("expected RttResponse, got {other:?}"),
    }
}

#[test]
fn network_characteristics_result_surfaces_as_autodetect() {
    let mut processor = make_processor();
    let request = AutoDetectRequest::netchar_result(7, 10, 50000, 20);
    let frame = encode_server_autodetect(request.clone());

    let outputs = process_frame(&mut processor, &frame);

    assert_eq!(outputs.len(), 1);
    match &outputs[0] {
        ironrdp_session::x224::ProcessorOutput::AutoDetect(req) => {
            assert_eq!(req, &request, "surfaced request must match the original");
        }
        other => panic!("expected AutoDetect output, got {other:?}"),
    }
}

#[test]
fn bandwidth_measure_start_does_not_crash() {
    let mut processor = make_processor();
    let request = AutoDetectRequest::bw_start_connect_time(100);
    let frame = encode_server_autodetect(request);

    let outputs = process_frame(&mut processor, &frame);
    assert!(outputs.is_empty(), "BW start should produce no output");
}

#[test]
fn bandwidth_measure_stop_does_not_crash() {
    let mut processor = make_processor();
    let request = AutoDetectRequest::bw_stop_continuous(200);
    let frame = encode_server_autodetect(request);

    let outputs = process_frame(&mut processor, &frame);
    assert_eq!(bandwidth_result(&outputs), (200, 0x000b, 1, 0));
}

#[test]
fn bandwidth_measure_payload_does_not_crash() {
    let mut processor = make_processor();
    let request = AutoDetectRequest::bw_payload(300, vec![0xAA; 64]);
    let frame = encode_server_autodetect(request);

    let outputs = process_frame(&mut processor, &frame);
    assert!(outputs.is_empty(), "BW payload should produce no output");
}

fn timed_request(
    processor: &mut Processor,
    request: AutoDetectRequest,
    millis: u64,
) -> Vec<ironrdp_session::x224::ProcessorOutput> {
    processor
        .process_with_timestamp(
            &encode_server_autodetect(request),
            &mut None,
            Some(ironrdp_core::MonotonicInstant::from_millis(millis)),
        )
        .expect("process timed auto-detect request")
}

fn bandwidth_result(outputs: &[ironrdp_session::x224::ProcessorOutput]) -> (u16, u16, u32, u32) {
    let [ironrdp_session::x224::ProcessorOutput::ResponseFrame(frame)] = outputs else {
        panic!("expected exactly one bandwidth response");
    };
    let X224(McsMessage::SendDataRequest(message)) = ironrdp_core::decode::<X224<McsMessage<'_>>>(frame).unwrap()
    else {
        panic!("expected main-channel response");
    };
    assert_eq!(message.channel_id, MESSAGE_CHANNEL_ID);
    let response = ironrdp_core::decode::<AutoDetectRspPdu>(&message.user_data).unwrap();
    let AutoDetectResponse::BandwidthMeasureResults {
        sequence_number,
        response_type,
        time_delta_ms,
        byte_count,
    } = response.response
    else {
        panic!("expected bandwidth results");
    };
    (sequence_number, response_type, time_delta_ms, byte_count)
}

#[test]
fn continuous_measurement_counts_data_without_security_headers() {
    let mut processor = make_processor();
    assert!(timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 10).is_empty());
    timed_request(&mut processor, AutoDetectRequest::rtt_continuous(2), 20);
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(3), 35);
    // RTT and Stop have six-byte auto-detect headers. Neither four-byte
    // security header, nor TPKT/X224/MCS framing, belongs to the count.
    assert_eq!(bandwidth_result(&result), (3, 0x000b, 25, 12));
}

#[test]
fn connect_time_measurement_includes_payload_headers_once() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_connect_time(1), 100);
    timed_request(&mut processor, AutoDetectRequest::bw_payload(2, vec![0xaa; 64]), 110);
    timed_request(&mut processor, AutoDetectRequest::rtt_continuous(3), 112);
    let result = timed_request(
        &mut processor,
        AutoDetectRequest::bw_stop_connect_time(4, vec![0xbb; 16]),
        140,
    );
    assert_eq!(bandwidth_result(&result), (4, 0x0003, 40, 64 + 8 + 16 + 8));
}

#[test]
fn repeated_start_resets_count_and_timer_and_stop_ends_window() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 100);
    timed_request(&mut processor, AutoDetectRequest::rtt_continuous(2), 110);
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(3), 200);
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(4), 210);
    assert_eq!(bandwidth_result(&result), (4, 0x000b, 10, 6));
    let repeated = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(5), 220);
    assert_eq!(bandwidth_result(&repeated), (5, 0x000b, 1, 0));
}

#[test]
fn measurement_timing_saturates_and_never_reports_zero_divisor() {
    for (start, stop, expected) in [(100, 100, 1), (100, 90, 1), (0, u64::MAX, u32::MAX)] {
        let mut processor = make_processor();
        timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), start);
        let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(2), stop);
        assert_eq!(bandwidth_result(&result), (2, 0x000b, expected, 6));
    }
}

#[test]
fn lossy_requests_on_main_channel_are_not_answered() {
    use ironrdp_pdu::rdp::autodetect::{BW_START_LOSSY_UDP, BW_STOP_LOSSY_UDP};
    let mut processor = make_processor();
    assert!(
        timed_request(
            &mut processor,
            AutoDetectRequest::BandwidthMeasureStart {
                sequence_number: 1,
                request_type: BW_START_LOSSY_UDP,
            },
            10
        )
        .is_empty()
    );
    assert!(
        timed_request(
            &mut processor,
            AutoDetectRequest::BandwidthMeasureStop {
                sequence_number: 1,
                request_type: BW_STOP_LOSSY_UDP,
                payload: None,
            },
            20
        )
        .is_empty()
    );
}

#[test]
fn untimed_driver_does_not_report_accumulated_bytes_as_a_real_measurement() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 10);
    timed_request(&mut processor, AutoDetectRequest::rtt_continuous(2), 20);
    let outputs = process_frame(
        &mut processor,
        &encode_server_autodetect(AutoDetectRequest::bw_stop_continuous(3)),
    );
    assert_eq!(bandwidth_result(&outputs), (3, 0x000b, 1, 0));
}

/// Frame a Save Session Info PDU on the I/O channel, as ordinary session data that arrives while
/// a continuous measurement is open. Returns the frame and the length of its MCS user data, which
/// is what [MS-RDPBCGR] 3.2.5.14 has the client count for it.
fn encode_io_channel_data() -> (Vec<u8>, u32) {
    use ironrdp_pdu::rdp::client_info::CompressionType;
    use ironrdp_pdu::rdp::headers::{
        CompressionFlags, ShareControlHeader, ShareControlPdu, ShareDataHeader, ShareDataPdu, StreamPriority,
    };
    use ironrdp_pdu::rdp::session_info::{InfoData, InfoType, SaveSessionInfoPdu};

    let control = ShareControlHeader {
        share_id: SHARE_ID,
        pdu_source: USER_CHANNEL_ID,
        share_control_pdu: ShareControlPdu::Data(ShareDataHeader {
            share_data_pdu: ShareDataPdu::SaveSessionInfo(SaveSessionInfoPdu {
                info_type: InfoType::PlainNotify,
                info_data: InfoData::PlainNotify,
            }),
            stream_priority: StreamPriority::Medium,
            compression_flags: CompressionFlags::empty(),
            compression_type: CompressionType::K8,
        }),
    };
    let user_data = encode_vec(&control).unwrap();
    let user_data_len = u32::try_from(user_data.len()).unwrap();

    let indication = McsMessage::SendDataIndication(SendDataIndication {
        initiator_id: USER_CHANNEL_ID,
        channel_id: IO_CHANNEL_ID,
        user_data: Cow::Owned(user_data),
    });

    (encode_vec(&X224(indication)).unwrap(), user_data_len)
}

#[test]
fn continuous_measurement_counts_io_channel_user_data() {
    let mut processor = make_processor();
    let (io_frame, io_user_data_len) = encode_io_channel_data();

    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(9), 1_000);
    for millis in [1_010, 1_020] {
        let outputs = processor
            .process_with_timestamp(
                &io_frame,
                &mut None,
                Some(ironrdp_core::MonotonicInstant::from_millis(millis)),
            )
            .expect("process I/O channel data");
        assert!(matches!(
            outputs.as_slice(),
            [ironrdp_session::x224::ProcessorOutput::SaveSessionInfo { .. }]
        ));
    }
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(10), 1_080);

    // Both I/O PDUs are counted from their Share Control header on, and the Stop from its
    // auto-detect header on (6 bytes); no TPKT, X.224, MCS or security header is.
    assert_eq!(
        bandwidth_result(&result),
        (10, 0x000b, 80, 2 * io_user_data_len + 6),
        "the Results echo the Stop's sequence number"
    );
}

#[test]
fn io_channel_data_outside_a_window_is_not_counted() {
    let mut processor = make_processor();
    let (io_frame, _) = encode_io_channel_data();

    // Data before the Start and after the Stop belongs to no window.
    process_frame(&mut processor, &io_frame);
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 500);
    let first = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(2), 520);
    assert_eq!(bandwidth_result(&first), (2, 0x000b, 20, 6));

    process_frame(&mut processor, &io_frame);
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(3), 600);
    let second = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(4), 640);
    assert_eq!(bandwidth_result(&second), (4, 0x000b, 40, 6));
}

/// A Stop of the other kind does not close the open window: a continuous Stop after a
/// connect-time Start was never timed against that Start, so it gets the untimed answer.
#[test]
fn stop_of_the_other_kind_preserves_the_open_measurement() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_connect_time(1), 100);
    timed_request(&mut processor, AutoDetectRequest::bw_payload(1, vec![0; 32]), 110);
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(2), 150);
    assert_eq!(bandwidth_result(&result), (2, 0x000b, 1, 0));
    let result = timed_request(
        &mut processor,
        AutoDetectRequest::bw_stop_connect_time(3, vec![0; 4]),
        200,
    );
    assert_eq!(bandwidth_result(&result), (3, 0x0003, 100, 32 + 8 + 4 + 8));
}

/// The complete Client Auto-Detect Response PDU as it goes on the wire
/// ([MS-RDPBCGR] 2.2.14.4 wrapping 2.2.14.2.2), inside an MCS Send Data Request from the user
/// channel to the message channel.
#[test]
fn bandwidth_results_are_sent_as_a_client_auto_detect_response_pdu() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(0x0102), 2_000);
    let outputs = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(0x0304), 2_300);

    let [ironrdp_session::x224::ProcessorOutput::ResponseFrame(frame)] = outputs.as_slice() else {
        panic!("expected exactly one response frame");
    };
    let X224(McsMessage::SendDataRequest(request)) = ironrdp_core::decode::<X224<McsMessage<'_>>>(frame).unwrap()
    else {
        panic!("expected an MCS Send Data Request");
    };
    assert_eq!(request.initiator_id, USER_CHANNEL_ID);
    assert_eq!(request.channel_id, MESSAGE_CHANNEL_ID);
    assert_eq!(
        request.user_data.as_ref(),
        [
            0x00, 0x20, // securityHeader.flags = SEC_AUTODETECT_RSP (0x2000)
            0x00, 0x00, // securityHeader.flagsHi
            0x0e, // headerLength
            0x01, // headerTypeId = TYPE_ID_AUTODETECT_RESPONSE
            0x04, 0x03, // sequenceNumber = 0x0304, the Stop's
            0x0b, 0x00, // responseType = 0x000B, continuous
            0x2c, 0x01, 0x00, 0x00, // timeDelta = 300 ms
            0x06, 0x00, 0x00, 0x00, // byteCount = 6, the Stop after its security header
        ]
    );
}

/// Network Characteristics Result PDUs carry no reply and do not disturb an open window.
#[test]
fn network_characteristics_result_is_counted_but_not_answered() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 0);
    let netchar = timed_request(&mut processor, AutoDetectRequest::netchar_result(2, 5, 90_000, 7), 5);
    assert!(matches!(
        netchar.as_slice(),
        [ironrdp_session::x224::ProcessorOutput::AutoDetect(
            AutoDetectRequest::NetworkCharacteristicsResult {
                bandwidth_kbps: Some(90_000),
                ..
            }
        )]
    ));
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(3), 10);
    // 18 bytes of Network Characteristics Result (all three fields) and 6 of Stop.
    assert_eq!(bandwidth_result(&result), (3, 0x000b, 10, 18 + 6));
}

#[test]
fn continuous_measurement_counts_static_channel_framing() {
    use core::any::TypeId;
    use ironrdp_dvc::DrdynvcClient;
    use ironrdp_dvc::pdu::{CapabilitiesRequestPdu, CapsVersion, DrdynvcServerPdu};

    let mut channels = StaticChannelSet::new();
    channels.insert(DrdynvcClient::new());
    channels.attach_channel_id(TypeId::of::<DrdynvcClient>(), 1005);
    let mut processor = Processor::new(
        channels,
        USER_CHANNEL_ID,
        IO_CHANNEL_ID,
        Some(MESSAGE_CHANNEL_ID),
        SHARE_ID,
    );
    let capabilities = encode_vec(&DrdynvcServerPdu::Capabilities(CapabilitiesRequestPdu::new(
        CapsVersion::V1,
        None,
    )))
    .unwrap();
    let frame = ironrdp_svc::server_encode_svc_messages(vec![capabilities.into()], 1005, USER_CHANNEL_ID).unwrap();
    let data_len = ironrdp_pdu::mcs::decode_send_data_indication(&frame)
        .unwrap()
        .user_data
        .len();

    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 10);
    let outputs = process_frame(&mut processor, &frame);
    assert!(matches!(
        outputs.as_slice(),
        [ironrdp_session::x224::ProcessorOutput::ResponseFrame(_)]
    ));
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(2), 30);
    assert_eq!(
        bandwidth_result(&result),
        (2, 0x000b, 20, u32::try_from(data_len).unwrap() + 6)
    );
}

#[test]
fn continuous_byte_count_saturates_instead_of_wrapping() {
    let mut processor = make_processor();
    timed_request(&mut processor, AutoDetectRequest::bw_start_continuous(1), 10);
    processor.autodetect_state_mut().record_data(usize::MAX);
    processor.autodetect_state_mut().record_data(42);
    let result = timed_request(&mut processor, AutoDetectRequest::bw_stop_continuous(2), 20);
    assert_eq!(bandwidth_result(&result), (2, 0x000b, 10, u32::MAX));
}

#[test]
fn continuous_measurement_counts_fast_path_updates_once() {
    use ironrdp_graphics::image_processing::PixelFormat;
    use ironrdp_pdu::Action;
    use ironrdp_pdu::fast_path::{EncryptionFlags, FastPathHeader, FastPathUpdatePdu, Fragmentation, UpdateCode};
    use ironrdp_session::image::DecodedImage;
    use ironrdp_session::{ActiveStageBuilder, ActiveStageOutput};

    let mut stage = ActiveStageBuilder {
        static_channels: StaticChannelSet::new(),
        user_channel_id: USER_CHANNEL_ID,
        io_channel_id: IO_CHANNEL_ID,
        message_channel_id: Some(MESSAGE_CHANNEL_ID),
        share_id: SHARE_ID,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
    }
    .build();
    let mut image = DecodedImage::new(PixelFormat::RgbA32, 1, 1);
    let update = encode_vec(&FastPathUpdatePdu {
        fragmentation: Fragmentation::Single,
        update_code: UpdateCode::Synchronize,
        compression_flags: None,
        compression_type: None,
        data: &[],
    })
    .unwrap();
    let mut fast_path = encode_vec(&FastPathHeader::new(EncryptionFlags::empty(), update.len())).unwrap();
    fast_path.extend_from_slice(&update);

    stage
        .process_with_timestamp(
            &mut image,
            Action::X224,
            &encode_server_autodetect(AutoDetectRequest::bw_start_continuous(1)),
            Some(ironrdp_core::MonotonicInstant::from_millis(10)),
        )
        .unwrap();
    stage.process(&mut image, Action::FastPath, &fast_path).unwrap();
    let outputs = stage
        .process_with_timestamp(
            &mut image,
            Action::X224,
            &encode_server_autodetect(AutoDetectRequest::bw_stop_continuous(2)),
            Some(ironrdp_core::MonotonicInstant::from_millis(30)),
        )
        .unwrap();
    let [ActiveStageOutput::ResponseFrame(frame)] = outputs.as_slice() else {
        panic!("expected bandwidth response");
    };
    assert_eq!(
        bandwidth_result(&[ironrdp_session::x224::ProcessorOutput::ResponseFrame(frame.clone())]),
        (2, 0x000b, 20, u32::try_from(update.len()).unwrap() + 6)
    );
}

proptest::proptest! {
    #[test]
    fn autodetect_state_machine_handles_arbitrary_request_sequences(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048)) {
        ironrdp_fuzzing::oracles::autodetect_state(&data);
    }
}
