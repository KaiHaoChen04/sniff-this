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
    datalink::{self, NetworkInterface},
    packet::{
        arp::{ArpOperation, ArpPacket},
        ethernet::{EtherType, EtherTypes, EthernetPacket},
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
    IPV4(String),
    IPV6(String),
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
        ArpOperation(1) => "Request",
        ArpOperation(2) => "Reply",
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

    (vlan_id, format!("PCP={}, DEI={}", pcp, dei))
}

fn format_frame(frame: &LinkLayerFrame, count: usize) -> String {
    let protocol_string = match &frame.protocol {
        LinkLayerProtocol::ARP(details) => format!("ARP     {}", details),
        LinkLayerProtocol::VLAN(id, details) => format!("VLAN     {}{}", id, details),
        LinkLayerProtocol::PPP(details) => format!("PPP      {}", details),
        LinkLayerProtocol::Tunnel(details) => format!("Tunnel     {}", details),
        LinkLayerProtocol::IPV4(details) => format!("IPV4     {}", details),
        LinkLayerProtocol::IPV6(details) => format!("IPV6     {}", details),
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
        .collect();

    let interfaces_names: Vec<_> = interfaces.iter().map(|name| name.name.clone()).collect();

    for name in &interfaces_names {
        interface_choice.add_choice(name);
    }
    interface_choice.set_value(0);

    let mut protocol_choices = Choice::new(220, 10, 200, 25, None);
    protocol_choices.add_choice("All Link Layers");
    protocol_choices.add_choice("ARP");
    protocol_choices.add_choice("VLAN");
    protocol_choices.add_choice("PPP");
    protocol_choices.add_choice("Tunnel");
    protocol_choices.add_choice("IPV4");
    protocol_choices.add_choice("IPV6");
    protocol_choices.set_value(0);

    let mut start_button = Button::new(440, 10, 70, 25, "Start");

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

    let (sender, receiver) = app::channel::<String>();

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
        let running = running.clone();
        let interfaces = interfaces.clone();
        let interfaces_choice = interface_choice.clone();
        let frame_count = frame_count.clone();
        let start_time = start_time.clone();
        let selected_protocol = selected_protocol.clone();
        let sender = sender.clone();

        move |b| {
            let mut is_running = running.lock().unwrap();
            if *is_running {
                *is_running = false;
                b.set_label("Start");
            } else {
                *is_running = true;
                b.set_label("Stop");
                let running = running.clone();
                let interfaces_index = interfaces_choice.value() as usize;

                if interfaces_index as i32 >= interfaces_choice.value().max(0)
                    && interfaces.is_empty()
                {
                    eprintln!("No interfaces available.");
                    *is_running = false;
                    b.set_label("Start");
                    return;
                }

                let interface = interfaces[interfaces_index].clone();
                let frame_count = frame_count.clone();
                let start_time = start_time.clone();
                let selected_protocol = selected_protocol.clone();
                let sender = sender.clone();

                thread::spawn(move || {
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

                    let (_tx, mut rx) = match datalink::channel(&interface, config) {
                        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
                        Ok(_) => {
                            eprintln!("Error: not an ethernet channel");
                            sender.send("Error: not an ethernet channel\n".to_string());
                            return;
                        }
                        Err(e) => {
                            eprintln!("Error creating channel: {}", e);
                            sender.send(format!("Error creating channel: {}\n", e));
                            return;
                        }
                    };
                    *start_time.lock().unwrap() = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap()
                        .as_micros() as u64;

                    while *running.lock().unwrap() {
                        match rx.next() {
                            Ok(packet) => {
                                eprintln!("got packet, len={}", packet.len());

                                if let Some(ethernet) = EthernetPacket::new(packet) {
                                    let protocol = match ethernet.get_ethertype() {
                                        EtherTypes::Arp => {
                                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                                LinkLayerProtocol::ARP(parse_arp_packets(&arp))
                                            } else {
                                                LinkLayerProtocol::Unknown(
                                                    "Malformed ARP".to_string(),
                                                )
                                            }
                                        }
                                        EtherTypes::Vlan => {
                                            if let Some(vlan) = VlanPacket::new(ethernet.payload())
                                            {
                                                let (id, details) = parse_vlan_packets(&vlan);
                                                LinkLayerProtocol::VLAN(id, details)
                                            } else {
                                                LinkLayerProtocol::Unknown(
                                                    "Malformed VLAN".to_string(),
                                                )
                                            }
                                        }
                                        EtherTypes::Ptp => {
                                            LinkLayerProtocol::PPP("PPP Frame".to_string())
                                        }
                                        EtherTypes::Mpls => {
                                            LinkLayerProtocol::Tunnel("MPLS frame".to_string())
                                        }
                                        EtherTypes::Ipv4 => {
                                            LinkLayerProtocol::IPV4("IPV4".to_string())
                                        }
                                        EtherTypes::Ipv6 => {
                                            LinkLayerProtocol::IPV6("IPV6".to_string())
                                        }

                                        other => {
                                            if other.0 == 34525 {
                                                let direction = if packet.len() == 74 {
                                                    "Request"
                                                } else if packet.len() == 86 {
                                                    "Response"
                                                } else {
                                                    "Unknown"
                                                };
                                                LinkLayerProtocol::Unknown(format!(
                                                    "Keepalive {} (Type 34525)",
                                                    direction
                                                ))
                                            } else {
                                                LinkLayerProtocol::Unknown(format!(
                                                    "Unknown {}",
                                                    other
                                                ))
                                            }
                                        }
                                    };
                                    let protocol_value = *selected_protocol.lock().unwrap();
                                    let should_display = match protocol_value {
                                        0 => true,
                                        1 => matches!(protocol, LinkLayerProtocol::ARP(_)),
                                        2 => matches!(protocol, LinkLayerProtocol::VLAN(_, _)),
                                        3 => matches!(protocol, LinkLayerProtocol::PPP(_)),
                                        4 => matches!(protocol, LinkLayerProtocol::Tunnel(_)),
                                        5 => matches!(protocol, LinkLayerProtocol::IPV4(_)),
                                        6 => matches!(protocol, LinkLayerProtocol::IPV6(_)),
                                        _ => false,
                                    };

                                    if should_display {
                                        let current_time = {
                                            let start = *start_time.lock().unwrap();
                                            let now = SystemTime::now()
                                                .duration_since(UNIX_EPOCH)
                                                .unwrap()
                                                .as_micros()
                                                as u64;
                                            (now - start) as f64 / 1_000_000.0
                                        };
                                        let frame = LinkLayerFrame {
                                            timestamp: current_time,
                                            source_mac: ethernet.get_source().to_string(),
                                            dest_mac: ethernet.get_destination().to_string(),
                                            protocol,
                                            length: packet.len(),
                                        };

                                        let mut count = frame_count.lock().unwrap();
                                        *count += 1;
                                        let formatted = format_frame(&frame, *count);

                                        sender.send(formatted);
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("Error capturing packet: {}", e);
                                sender.send(format!("Error capturing packet {}\n", e));
                                break;
                            }
                        }
                    }
                });
            }
        }
    });

    while app.wait() {
        if let Some(msg) = receiver.recv() {
            buffer.append(&msg);
            text_display.set_insert_position(buffer.length());
            text_display.show_insert_position();
        }
    }
}
