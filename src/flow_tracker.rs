extern crate time;
extern crate postgres;

use std::ops::Sub;
use std::time::{Duration, Instant};
use std::collections::{HashSet, VecDeque};
use aes::cipher::typenum::private::IsGreaterPrivate;
use clap::Error;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::tcp::{TcpPacket, TcpFlags, TcpOptionNumber};
use rand::prelude::ThreadRng;
use std::net::{IpAddr};
use log::{error, info};
use std::{thread};
use postgres::{Client, NoTls};
use rand::Rng;
use std::io::Write;
use std::fs::OpenOptions;
use memuse::DynamicUsage;

use crate::cache::{MeasurementCache, MEASUREMENT_CACHE_FLUSH};
use crate::ocsp_struct::OCSP_MEASURE;
use crate::stats_tracker::{StatsTracker};
use crate::common::{TimedFlow, Flow, u8_to_u32_be};

pub struct FlowTracker {
    flow_timeout: Duration,
    tcp_dsn: Option<String>,
    cache: MeasurementCache,
    pub stats: StatsTracker,
    tracked_tcp_flows: HashSet<Flow>,
    stale_tcp_drops: VecDeque<TimedFlow>,
    tracked_udp_flows: HashSet<Flow>,
    stale_udp_drops: VecDeque<TimedFlow>,
    prevented_udp_flows: HashSet<Flow>,
    stale_udp_preventions: VecDeque<TimedFlow>,
    rand: ThreadRng,
    pub gre_offset: usize,
}

impl FlowTracker {
    pub fn new(tcp_dsn: Option<String>, core_id: i8, total_cores: i32, gre_offset: usize) -> FlowTracker {
        let mut ft = FlowTracker {
            flow_timeout: Duration::from_secs(20),
            tcp_dsn: tcp_dsn,
            cache: MeasurementCache::new(),
            stats: StatsTracker::new(),
            tracked_tcp_flows: HashSet::new(),
            stale_tcp_drops: VecDeque::with_capacity(65536),
            tracked_udp_flows: HashSet::new(),
            stale_udp_drops: VecDeque::with_capacity(65536),
            prevented_udp_flows: HashSet::new(),
            stale_udp_preventions: VecDeque::with_capacity(65536),
            rand: rand::thread_rng(),
            gre_offset: gre_offset,
        };

        ft.cache.last_flush = ft.cache.last_flush.sub(time::Duration::seconds(
            (core_id as i64) * MEASUREMENT_CACHE_FLUSH / (total_cores as i64)
        ));
        ft
    }

    pub fn handle_ipv4_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv4_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv4_pkt = match eth_pkt.get_ethertype() {
            EtherTypes::Vlan => Ipv4Packet::new(&eth_pkt.payload()[4..]),
            _ => Ipv4Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv4_pkt) = ipv4_pkt {
            match ipv4_pkt.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(&ipv4_pkt.payload()) {
                        self.handle_tcp_packet(
                            IpAddr::V4(ipv4_pkt.get_source()),
                            IpAddr::V4(ipv4_pkt.get_destination()),
                            &tcp_pkt,
                            ipv4_pkt.get_ecn(),
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv4_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V4(ipv4_pkt.get_source()),
                            IpAddr::V4(ipv4_pkt.get_destination()),
                            &udp_pkt,
                            ipv4_pkt.get_ecn(),
                        )
                    }
                }
                _ => {}
            }
        }
    }

    pub fn handle_ipv6_packet(&mut self, eth_pkt: &EthernetPacket) {
        self.stats.total_packets += 1;
        self.stats.ipv6_packets += 1;
        self.stats.bytes_processed += eth_pkt.packet().len() as u64;
        let ipv6_pkt = match eth_pkt.get_ethertype() {
             EtherTypes::Vlan => Ipv6Packet::new(&eth_pkt.payload()[4..]),
             _ => Ipv6Packet::new(eth_pkt.payload()),
        };
        if let Some(ipv6_pkt) = ipv6_pkt {
            match ipv6_pkt.get_next_header() {
                IpNextHeaderProtocols::Tcp => {
                    if let Some(tcp_pkt) = TcpPacket::new(ipv6_pkt.payload()) {
                        self.handle_tcp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &tcp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv6_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &udp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                },
                IpNextHeaderProtocols::Udp => {
                    if let Some(udp_pkt) = UdpPacket::new(&ipv6_pkt.payload()) {
                        self.handle_udp_packet(
                            IpAddr::V6(ipv6_pkt.get_source()),
                            IpAddr::V6(ipv6_pkt.get_destination()),
                            &udp_pkt,
                            ipv6_pkt.get_traffic_class() & 0b0000011,
                        )
                    }
                }
                _ => return,
            }
        }
    }

    pub fn handle_udp_packet(&mut self, source: IpAddr, destination: IpAddr, udp_pkt: &UdpPacket, ecn: u8) {
        self.stats.udp_packets_seen += 1;
        let flow = Flow::new_udp(&source, &destination, &udp_pkt);
        if self.tracked_udp_flows.contains(&flow) {
            // Packets coming from client
        } else if self.tracked_udp_flows.contains(&flow.reversed_clone()) {
            // Packets coming from server
        } else {
            // New flow
            if self.rand.gen_range(0..10) > -1 {
                // Allows for random sampling of UDP flows
                self.begin_tracking_udp_flow(&flow);
            } else {
                self.prevent_tracking_udp_flow(&flow);
            }
        }
        if udp_pkt.payload().len() == 0 {
            return;
        }
        match (udp_pkt.get_destination(), udp_pkt.get_source()) {
            (_, _) => {},
        }

    }

    pub fn handle_tcp_packet(&mut self, source: IpAddr, destination: IpAddr, tcp_pkt: &TcpPacket, ecn: u8) {
        self.stats.tcp_packets_seen += 1;
        let flow = Flow::new_tcp(&source, &destination, &tcp_pkt);
        let tcp_flags = tcp_pkt.get_flags();
        for option in tcp_pkt.get_options_iter() {
            // Iterates over each tcp pkt option
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) == 0 {
            // New TCP Flow
            self.stats.connections_seen += 1;
            if self.rand.gen_range(0..10) > -1 {
                // Allows for random sampling of TCP flows
                self.stats.connections_started += 1;
                self.begin_tracking_tcp_flow(&flow, tcp_pkt.packet().to_vec());
            }
            return
        }
        if (tcp_flags & TcpFlags::SYN) != 0 && (tcp_flags & TcpFlags::ACK) != 0 {
            if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server response to 3-way handshake (SYN ACK)
            }
            return
        }
        if (tcp_flags & TcpFlags::FIN) != 0 || (tcp_flags & TcpFlags::RST) != 0 {
            if self.tracked_tcp_flows.contains(&flow) {
                // Client closed the connection
            } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
                // Server closed the connection
            }
            self.tracked_tcp_flows.remove(&flow);
            self.stats.connections_closed += 1;
            return
        }
        if tcp_pkt.payload().len() == 0 {
            return
        }
        if self.tracked_tcp_flows.contains(&flow) {
            // Client data packet

        } else if self.tracked_tcp_flows.contains(&flow.reversed_clone()) {
            // Server data packet
        }

        match (tcp_pkt.get_destination(), tcp_pkt.get_source()) {
            (80, _) => self.handle_http_record(true, source, destination, tcp_pkt.payload(), &flow),
            (_, 80) => self.handle_http_record(false, source, destination, tcp_pkt.payload(), &flow.reversed_clone()),
            (_, _) => {},
        }

        // once in a while -- flush everything
        if time::now().to_timespec().sec - self.cache.last_flush.to_timespec().sec >
            MEASUREMENT_CACHE_FLUSH {
            self.flush_to_db()
        }
    }

    fn handle_http_record(&mut self, is_client: bool, source: IpAddr, destination: IpAddr, record: &[u8], flow: &Flow) {
        if is_client {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut req = httparse::Request::new(&mut headers);
            let res = req.parse(record).unwrap();
            if res.is_complete() {
                for header in req.headers.iter() {
                    if header.name == "Content-Type" && header.value == b"application/ocsp-request" {
                        self.handle_ocsp_record(true, source, destination, &record[res.unwrap()..], flow);
                    }
                }
            }
        } else {
            let mut headers = [httparse::EMPTY_HEADER; 16];
            let mut resp = httparse::Response::new(&mut headers);
            let res = resp.parse(record).unwrap();
            if res.is_complete() {
                for header in resp.headers.iter() {
                    if header.name == "Content-Type" && header.value == b"application/ocsp-response" {
                        self.handle_ocsp_record(false, source, destination, &record[res.unwrap()..], flow);
                    }
                }
            }
        }
    }

    fn handle_ocsp_record(&mut self, is_request: bool, source: IpAddr, destination: IpAddr, record: &[u8], flow: &Flow) {
        if !is_request {
            let measurement = OCSP_MEASURE::new(source, destination, record.to_vec());
            self.cache.add_ocsp_measurement(flow, measurement);
        }
    }

    pub fn flush_to_db(&mut self) {
        let ocsp_cache = self.cache.flush_ocsp_measurements();

        if self.tcp_dsn != None {
            let tcp_dsn = self.tcp_dsn.clone().unwrap();
            thread::spawn(move || {
                let inserter_thread_start = time::now();
                let mut thread_db_conn = Client::connect(&tcp_dsn, NoTls).unwrap();
                
                let insert_ocsp = match thread_db_conn.prepare(
                    "INSERT
                    INTO ocsp_measurements (
                        time,
                        server_ip,
                        response)
                    VALUES ($1, $2, $3);"
                )
                {
                    Ok(stmt) => stmt,
                    Err(e) => {
                        error!("Preparing insert_ocsp failed: {}", e);
                        return;
                    }
                };

                for (_flow, measurement) in ocsp_cache {
                    let mut db_ip = None;
                    if let IpAddr::V4(ipv4) = measurement.server_ip {
                        let octets = ipv4.octets();
                        db_ip = Some(u8_to_u32_be(octets[0], octets[1], octets[2], octets[3]));
                    }
                    let updated_rows = thread_db_conn.execute(&insert_ocsp, &[&(measurement.time), &(db_ip), &(measurement.response)]);
                    if updated_rows.is_err() {
                        error!("Error updating primers: {:?}", updated_rows)
                    }
                }
            });
        }
    }

    fn begin_tracking_tcp_flow(&mut self, flow: &Flow, _syn_data: Vec<u8>) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_tcp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_tcp_flows.insert(*flow);
    }

    fn begin_tracking_udp_flow(&mut self, flow: &Flow) {
        // Always push back, even if the entry was already there. Doesn't hurt
        // to do a second check on overdueness, and this is simplest.
        self.stale_udp_drops.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.tracked_udp_flows.insert(*flow);
    }

    fn prevent_tracking_udp_flow(&mut self, flow: &Flow) {
        self.stale_udp_preventions.push_back(TimedFlow {
            event_time: Instant::now(),
            flow: *flow,
        });
        self.prevented_udp_flows.insert(*flow);
    }

    pub fn cleanup(&mut self) {
        while !self.stale_tcp_drops.is_empty() &&
            self.stale_tcp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_tcp_drops.pop_front().unwrap();
            self.tracked_tcp_flows.remove(&cur.flow);
        }
        while !self.stale_udp_drops.is_empty() &&
            self.stale_udp_drops.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_udp_drops.pop_front().unwrap();
            self.tracked_udp_flows.remove(&cur.flow);
        }
        while !self.stale_udp_preventions.is_empty() &&
            self.stale_udp_preventions.front().unwrap().event_time.elapsed() >= self.flow_timeout {
            let cur = self.stale_udp_preventions.pop_front().unwrap();
            self.prevented_udp_flows.remove(&cur.flow);
        }
    }

    pub fn debug_print(&mut self) {
        info!("tracked_tcp_flows: {} stale__tcp_drops: {}", self.tracked_tcp_flows.dynamic_usage(), self.stale_tcp_drops.dynamic_usage());
        info!("tracked_udp_flows: {} stale__udp_drops: {}", self.tracked_udp_flows.dynamic_usage(), self.stale_udp_drops.dynamic_usage());
        info!("Size of UDP Preventions: {}, Size of UDP Preventions Flush: {}", self.prevented_udp_flows.dynamic_usage(), self.stale_udp_preventions.dynamic_usage());
    }

    pub fn log_packet(&mut self, contents: &String, file_path: &str) -> std::io::Result<()> {
        let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .open(file_path)?;
        file.write_all(contents.as_bytes())?;
        Ok(())
    }
}
