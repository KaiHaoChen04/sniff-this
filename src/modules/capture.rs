use crate::modules::{
    frame::LinkLayerFrame,
    protocols::{parse_arp_packet, parse_vlan_packet, LinkLayerProtocol},
};
use pnet::{
    datalink::{self, NetworkInterface},
    packet::{
        arp::ArpPacket,
        ethernet::{EtherTypes, EthernetPacket},
        vlan::VlanPacket,
        Packet,
    },
};
use std::{
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub fn list_interfaces() -> Vec<NetworkInterface> {
    datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .collect()
}

fn classify_ethernet(ethernet: &EthernetPacket, packet_len: usize) -> LinkLayerProtocol {
    match ethernet.get_ethertype() {
        EtherTypes::Arp => ArpPacket::new(ethernet.payload())
            .map(|arp| LinkLayerProtocol::ARP(parse_arp_packet(&arp)))
            .unwrap_or_else(|| LinkLayerProtocol::Unknown("Malformed ARP".into())),
        EtherTypes::Vlan => VlanPacket::new(ethernet.payload())
            .map(|vlan| {
                let (id, details) = parse_vlan_packet(&vlan);
                LinkLayerProtocol::VLAN(id, details)
            })
            .unwrap_or_else(|| LinkLayerProtocol::Unknown("Malformed VLAN".into())),
        EtherTypes::Ptp => LinkLayerProtocol::PPP("PPP Frame".into()),
        EtherTypes::Mpls => LinkLayerProtocol::Tunnel("MPLS frame".into()),
        EtherTypes::Ipv4 => LinkLayerProtocol::IPV4("IPV4".into()),
        EtherTypes::Ipv6 => LinkLayerProtocol::IPV6("IPV6".into()),
        other if other.0 == 34525 => {
            let direction = match packet_len {
                74 => "Request",
                86 => "Response",
                _ => "Unknown",
            };
            LinkLayerProtocol::Unknown(format!("Keepalive {} (Type 34525)", direction))
        }
        other => LinkLayerProtocol::Unknown(format!("Unknown {}", other)),
    }
}

fn protocol_matches_filter(protocol: &LinkLayerProtocol, filter: usize) -> bool {
    match filter {
        0 => true,
        1 => matches!(protocol, LinkLayerProtocol::ARP(_)),
        2 => matches!(protocol, LinkLayerProtocol::VLAN(_, _)),
        3 => matches!(protocol, LinkLayerProtocol::PPP(_)),
        4 => matches!(protocol, LinkLayerProtocol::Tunnel(_)),
        5 => matches!(protocol, LinkLayerProtocol::IPV4(_)),
        6 => matches!(protocol, LinkLayerProtocol::IPV6(_)),
        _ => false,
    }
}

/// Runs the capture loop until `running` is set false.
/// `on_frame` is called with each formatted, already-filtered line
/// so this function has no idea a GUI exists.
pub fn run_capture(
    interface: NetworkInterface,
    running: Arc<Mutex<bool>>,
    frame_count: Arc<Mutex<usize>>,
    selected_protocol: Arc<Mutex<usize>>,
    on_frame: impl Fn(String) + Send + 'static,
) {
    let config = datalink::Config {
        write_buffer_size: 4096,
        read_buffer_size: 4096,
        read_timeout: None,
        write_timeout: None,
        channel_type: datalink::ChannelType::Layer2,
        bpf_fd_attempts: 1000,
        linux_fanout: None,
        promiscuous: true,
        socket_fd: None,
    };

    let mut rx = match datalink::channel(&interface, config) {
        Ok(datalink::Channel::Ethernet(_tx, rx)) => rx,
        Ok(_) => {
            on_frame("Error: not an ethernet channel\n".to_string());
            return;
        }
        Err(e) => {
            on_frame(format!("Error creating channel: {}\n", e));
            return;
        }
    };

    let start_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_micros() as u64;

    while *running.lock().unwrap() {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet) = EthernetPacket::new(packet) {
                    let protocol = classify_ethernet(&ethernet, packet.len());
                    let filter = *selected_protocol.lock().unwrap();

                    if protocol_matches_filter(&protocol, filter) {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64;
                        let timestamp = (now - start_time) as f64 / 1_000_000.0;

                        let frame = LinkLayerFrame {
                            timestamp,
                            source_mac: ethernet.get_source().to_string(),
                            dest_mac: ethernet.get_destination().to_string(),
                            protocol,
                            length: packet.len(),
                        };

                        let mut count = frame_count.lock().unwrap();
                        *count += 1;
                        on_frame(crate::modules::frame::format_frame(&frame, *count));
                    }
                }
            }
            Err(e) => {
                on_frame(format!("Error capturing packet {}\n", e));
                break;
            }
        }
    }
}
