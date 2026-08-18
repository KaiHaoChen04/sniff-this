use fltk::{
    app,
    button::Button,
    enums::Font,
    menu::Choice,
    prelude::*,
    text::{TextBuffer, TextDisplay},
    window::Window,
};
use pnet::{
    datalink,
    packet::{
        arp::{ArpOperation, ArpPacket},
        ethernet::{EtherType, EthernetPacket},
        vlan::VlanPacket,
        Packet,
    },
};
use std::{
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use fltk_theme::{color_themes, ColorTheme, ThemeType, WidgetTheme};

#[derive(Debug)]
enum LinkLayerProtocol {
    ARP(String),
    VLAN(u16, String),
    PPP(String),
    Tunnel(String),
    Unknown(String),
}

struct LinkLayerFrame {
    timestamp: f64,
    source_mac: String,
    dest_mac: String,
    protocol: LinkLayerProtocol,
    length: usize,
}

fn parse_arp_packets(arp_packets: &ArpPacket) -> String {
    let operation = match arp_packets.get_operation() {
        ArpOperation(0) => "Request",
        ArpOperation(1) => "Reply",
        _ => "Unknown",
    };
    format!(
        "{} Sender: {}({}) -> Target: {}({})",
        operation,
        arp_packets.get_sender_hw_addr(),
        arp_packets.get_sender_proto_addr(),
        arp_packets.get_target_hw_addr(),
        arp_packets.get_target_proto_addr(),
    )
}
fn parse_vlan_packets(vlan_packets: &VlanPacket) -> (u16, String) {
    let vlan_id = vlan_packets.get_vlan_identifier();
    let pcp = vlan_packets.get_priority_code_point().0;
    let dei = vlan_packets.get_drop_eligible_indicator();

    // Might add eternet type in later
    (vlan_id, format!("PCP={}, DEI={}", pcp, dei))
}

fn format_frame(frame: &LinkLayerFrame, count: usize) -> String {
    let protocol_string = match &frame.protocol {
        LinkLayerProtocol::ARP(details) => format!("ARP     {}", details),
        LinkLayerProtocol::VLAN((id), (details)) => format!("VLAN     {}{}", id, details),
        LinkLayerProtocol::PPP(details) => format!("PPP      {}", details),
        LinkLayerProtocol::Tunnel(details) => format!("Tunnel     {}", details),
        LinkLayerProtocol::Unknown(details) => format!("Unknown    {}", details),
    };

    format!(
        "{:>6} {:>12.6} {:>18} -> {:>18} {:>4} {}\n",
        count, frame.timestamp, frame.source_mac, frame.dest_mac, frame.length, protocol_string,
    )
}

fn main() {}
