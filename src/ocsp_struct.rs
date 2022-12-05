use std::net::IpAddr;

#[derive(Clone)]
pub struct OCSP_MEASURE {
    pub time: i64,

    pub server_ip: IpAddr,
    client_ip: IpAddr,

    pub response: Vec<u8>,
}

impl OCSP_MEASURE {
    pub fn new(src_ip: IpAddr, dst_ip: IpAddr, response: Vec<u8>) -> OCSP_MEASURE {
        let curr_time = time::now().to_timespec().sec;

        OCSP_MEASURE {
            time: curr_time,
            server_ip: src_ip,
            client_ip: dst_ip,
            response: response,
        }
    }
}