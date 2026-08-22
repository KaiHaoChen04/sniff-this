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

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Gtk);
    let theme = ColorTheme::new(color_themes::DARK_THEME);
    theme.apply();

    let mut wind = Window::new(100, 100, 1200, 600, "Sniff This");

    let mut interface_choice = Choice::new(10, 10, 200, 25, None);
    let interfaces: Vec<_> = datalink::interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .map(|i_name| i_name.name)
        .collect();

    for name in &interfaces {
        interface_choice.add_choice(name);
    }
    interface_choice.set_value(0);

    let mut protocol_choices = Choice::new(10, 10, 200, 25, None);
    protocol_choices.add_choice("All Link Layers");
    protocol_choices.add_choice("ARP");
    protocol_choices.add_choice("VLAN");
    protocol_choices.add_choice("PPP");
    protocol_choices.add_choice("Tunnel");
    protocol_choices.set_value(0);

    let mut start_button = Button::new(300, 10, 70, 25, "Start");

    let mut text_display = TextDisplay::new(10, 45, 1180, 545, None);
    text_display.set_text_font(Font::Courier);
    let mut buffer = TextBuffer::default();
    text_display.set_buffer(buffer.clone());

    buffer.append(&format!(
        "{:>6} {:>12} {:>18} {:>20} {:>4} {}\n",
        "No.", "Time", "Source MAC", "Dest MAC", "Len", "Protocol & Details"
    ));

    buffer.append(&"-".repeat(100));
    buffer.append("\n");

    wind.end();
    wind.show();

    let buffer = Arc::new(Mutex::new(buffer));
    let running = Arc::new(Mutex::new(false));
    let frame_count = Arc::new(Mutex::new(0));
    let start_time = Arc::new(Mutex::new(0u64));
    let selected_protocol = Arc::new(Mutex::new(0));

    protocol_choices.set_callback({
        let curr_protocol = selected_protocol.clone();
        move |c| {
            *curr_protocol.lock().unwrap() = c.value();
        }
    });

    start_button.set_callback({
        let buffer = buffer.clone();
        let running = running.clone();
        let interfaces = interfaces.clone();
        let interfaces_choice = interface_choice.clone();
        let frame_count = frame_count.clone();
        let start_time = start_time.clone();
        let selected_protocol = selected_protocol.clone();

        move |b| {
            let mut is_running = running.lock().unwrap();
            if *is_running {
                *is_running = false;
                b.set_label("Start");
            } else {
                *is_running = true;
            }
        }
    });
}
