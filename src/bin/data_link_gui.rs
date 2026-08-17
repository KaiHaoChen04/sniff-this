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

fn main() {}
