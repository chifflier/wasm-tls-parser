use nom::Err;
use tls_parser::*;
use wasm_sc_guest::*;
use x509_parser::parse_x509_der;

// #[no_mangle]
// pub static PROTOCOL: &str = "tls";
#[no_mangle]
pub static TYPE: &str = "streaming";
#[no_mangle]
pub static FILTER: &str = "tcp";

// export a Rust function called `init`
#[no_mangle]
pub fn init(_major: u32, _minor: u32) -> i32 {
    /* ... */
    SCLogInfo!("hello, wasm");
    0
}

#[no_mangle]
pub fn stream_log(i: &[u8], _tx_id: u64) -> i32 {
    /* ... */
    SCLogNotice!("rs/stream_log");
    // unsafe {
    //     let ptr = SCFlowAppLayerProto();
    //     let s = CStr::from_ptr(ptr as *const i8);
    //     SCLogDebug!("{:?}", s);
    //     sc_free(ptr);
    // }
    if i.is_empty() {
        return 0;
    }
    // XXX debug: print buffer as hex
    SCLogNotice!("{:x?}", i);
    // real parsing
    parse_tcp_level(i)
}

#[no_mangle]
pub fn tx_log(_tx_id: u64) -> i32 {
    SCLogNotice!("rs/tx_log");
    // {
    //     // only available in Tx logger
    //     let mut sec = 0;
    //     let mut usec = 0;
    //     unsafe { SCPacketTimestamp(&mut sec, &mut usec) };
    //     SCLogInfo!("sec: {}, usec: {}", sec, usec);
    // }
    let serial = tls_get_cert_serial().unwrap();
    SCLogInfo!("serial: {}", serial);
    0
}

fn parse_tcp_level(input: &[u8]) -> i32 {
    // XXX we have a list of (fragmented) records (and we parse only one)
    let mut i = input;
    let mut status = 0;
    while !i.is_empty() {
        match parse_tls_raw_record(i) {
            Ok((rem, ref r)) => {
                status = parse_record_level(r);
                // let res = parse_tls_plaintext(i);
                // SCLogDebug!("{:x?}", res);
                i = rem;
            }
            Err(Err::Incomplete(needed)) => {
                SCLogInfo!("Fragmentation required (tcp): {:?}", needed);
                break;
            }
            Err(e) => {
                SCLogInfo!("Parsing failed: {:?}", e);
                return -1;
            }
        }
    }
    status
}

fn parse_record_level(raw_record: &TlsRawRecord) -> i32 {
    SCLogInfo!("parse_record_level {}", raw_record.data.len());
    match raw_record.hdr.record_type {
        TlsRecordType::ChangeCipherSpec => (),
        TlsRecordType::Handshake => (),
        TlsRecordType::Alert => (),
        _ => return 0,
    }
    match parse_tls_record_with_header(raw_record.data, &raw_record.hdr) {
        Ok((rem2, ref msg_list)) => {
            for msg in msg_list {
                parse_message_level(&msg);
            }
        }
        Err(Err::Incomplete(needed)) => SCLogInfo!("Fragmentation required (record): {:?}", needed),
        Err(e) => SCLogInfo!("Parsing failed: {:?}", e),
    }
    0
}

fn parse_message_level(msg: &TlsMessage) {
    SCLogInfo!("msg: {:?}", msg);
    match msg {
        TlsMessage::Handshake(ref m) => match m {
            TlsMessageHandshake::ClientHello(ref content) => {
                SCLogInfo!(
                    "TLS ClientHello version=0x{:x} ({:?})",
                    content.version,
                    content.version
                );
            }
            TlsMessageHandshake::Certificate(ref content) => {
                for cert in &content.cert_chain {
                    SCLogInfo!("cert: {:?}", cert);
                    match parse_x509_der(cert.data) {
                        Ok((_rem, x509)) => {
                            let tbs = &x509.tbs_certificate;
                            SCLogInfo!("X.509 Subject: {}", tbs.subject);
                            SCLogInfo!("X.509 Serial: {:X}", tbs.serial);
                            SCLogInfo!("X.509 is CA?: {}", tbs.is_ca());
                        }
                        _ => SCLogInfo!("Could not decode X.509 certificate"),
                    }
                }
            }
            _ => (),
        },
        _ => (),
    }
}
