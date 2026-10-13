use data_link_lib::{list_header, list_interfaces, list_local, run_capture, CapturedPacket};
use fltk::{
    app,
    browser::HoldBrowser,
    button::Button,
    enums::{Align, Font},
    frame::Frame,
    menu::Choice,
    prelude::*,
    text::{TextBuffer, TextDisplay, WrapMode},
    window::Window,
};
use fltk_theme::{color_themes, ColorTheme};
use std::sync::{Arc, Mutex};
use std::thread;

fn refresh_lan_list(browser: &mut HoldBrowser, header: &mut Frame) {
    match list_local() {
        Ok(ips) => {
            browser.clear();
            if ips.is_empty() {
                browser.add("No private IPs found.");
                header.set_label("Local Network (0 hosts)");
            } else {
                for ip in &ips {
                    browser.add(ip);
                }
                header.set_label(&format!("Local Network ({} hosts)", ips.len()));
            }
        }
        Err(e) => {
            browser.clear();
            browser.add(&format!("Error: {}", e));
            header.set_label("Local Network (error)");
            eprintln!("list_local failed: {}", e);
        }
    }
}

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Gtk);
    ColorTheme::new(color_themes::DARK_THEME).apply();

    let mut wind = Window::new(100, 100, 1200, 700, "Sniff This");

    let mut interface_choice = Choice::new(10, 10, 200, 25, None);
    let interfaces = list_interfaces();
    for iface in &interfaces {
        interface_choice.add_choice(&iface.name);
    }
    interface_choice.set_value(0);

    let mut protocol_choices = Choice::new(220, 10, 200, 25, None);
    for label in [
        "All Link Layers",
        "ARP",
        "VLAN",
        "PPP",
        "Tunnel",
        "IPV4",
        "IPV6",
    ] {
        protocol_choices.add_choice(label);
    }
    protocol_choices.set_value(0);

    let mut start_button = Button::new(440, 10, 70, 25, "Start");
    let mut lan_button = Button::new(520, 10, 80, 25, "LAN IPs");

    let list_header_text = list_header();
    let mut list_header = Frame::new(10, 42, 1180, 20, list_header_text.as_str());
    list_header.set_align(Align::Left | Align::Inside);
    list_header.set_label_font(Font::Courier);
    list_header.set_label_size(12);

    let mut packet_list = HoldBrowser::new(10, 62, 1180, 330, None);
    packet_list.set_text_size(12);
    // HoldBrowser has no set_text_font API, so force the monospace Courier
    // face (FLTK font 4) per row. '@' is the format char; escape any
    // literal '@' in packet text as '@@' so columns never shift.
    packet_list.set_format_char('@');

    let mut detail_header = Frame::new(10, 398, 1180, 20, "Hex Payload (click a packet above)");
    detail_header.set_align(Align::Left | Align::Inside);
    detail_header.set_label_size(12);

    let mut detail_display = TextDisplay::new(10, 418, 1180, 272, None);
    detail_display.set_text_font(Font::Courier);
    detail_display.set_text_size(12);
    detail_display.wrap_mode(WrapMode::AtBounds, 0);
    let mut detail_buffer = TextBuffer::default();
    detail_display.set_buffer(detail_buffer.clone());
    detail_buffer.append("Click a packet to view its hex payload.\n");

    wind.end();
    wind.show();

    // Popup window listing private IPs on the local network.
    // Kept hidden until the "LAN IPs" button is clicked.
    let lan_win = Window::new(300, 200, 360, 420, "Local Network IPs");
    let mut lan_header = Frame::new(10, 10, 340, 20, "Local Network");
    lan_header.set_align(Align::Left | Align::Inside);
    lan_header.set_label_size(12);
    let mut lan_list = HoldBrowser::new(10, 35, 340, 340, None);
    lan_list.set_text_size(12);
    let mut lan_refresh = Button::new(10, 380, 165, 30, "Refresh");
    let mut lan_close = Button::new(185, 380, 165, 30, "Close");
    lan_win.end();

    let (sender, receiver) = app::channel::<CapturedPacket>();
    let running = Arc::new(Mutex::new(false));
    let frame_count = Arc::new(Mutex::new(0));
    let selected_protocol = Arc::new(Mutex::new(0));
    let packets: Arc<Mutex<Vec<CapturedPacket>>> = Arc::new(Mutex::new(Vec::new()));

    // Click a row -> show that packet's stored hex detail.
    packet_list.set_callback({
        let packets = packets.clone();
        let mut detail_buffer = detail_buffer.clone();
        move |b| {
            let selected = b.value();
            if selected <= 0 {
                return;
            }
            let idx = (selected - 1) as usize;
            if let Some(packet) = packets.lock().unwrap().get(idx) {
                detail_buffer.set_text(&packet.detail);
            }
        }
    });

    protocol_choices.set_callback({
        let selected_protocol = selected_protocol.clone();
        move |c| *selected_protocol.lock().unwrap() = c.value() as usize
    });

    start_button.set_callback({
        let running = running.clone();
        let interface_choice = interface_choice.clone();
        let frame_count = frame_count.clone();
        let selected_protocol = selected_protocol.clone();
        let packets = packets.clone();
        let mut packet_list = packet_list.clone();
        let mut detail_buffer = detail_buffer.clone();

        move |b| {
            let mut is_running = running.lock().unwrap();
            if *is_running {
                *is_running = false;
                b.set_label("Start");
            } else {
                if interfaces.is_empty() {
                    eprintln!("No interfaces available.");
                    return;
                }
                let index = interface_choice.value() as usize;
                if index >= interfaces.len() {
                    eprintln!("No interface selected.");
                    return;
                }
                *is_running = true;
                b.set_label("Stop");

                // Fresh capture: keep list rows 1:1 with stored packets.
                *frame_count.lock().unwrap() = 0;
                packets.lock().unwrap().clear();
                packet_list.clear();
                detail_buffer.set_text("Click a packet to view its hex payload.\n");

                let interface = interfaces[index].clone();
                let running = running.clone();
                let frame_count = frame_count.clone();
                let selected_protocol = selected_protocol.clone();

                thread::spawn(move || {
                    run_capture(
                        interface,
                        running,
                        frame_count,
                        selected_protocol,
                        move |packet| {
                            sender.send(packet);
                        },
                    );
                });
            }
        }
    });

    lan_button.set_callback({
        let mut lan_win = lan_win.clone();
        let mut lan_list = lan_list.clone();
        let mut lan_header = lan_header.clone();
        move |_| {
            refresh_lan_list(&mut lan_list, &mut lan_header);
            lan_win.show();
        }
    });

    lan_refresh.set_callback({
        let mut lan_list = lan_list.clone();
        let mut lan_header = lan_header.clone();
        move |_| refresh_lan_list(&mut lan_list, &mut lan_header)
    });

    lan_close.set_callback({
        let mut lan_win = lan_win.clone();
        move |_| lan_win.hide()
    });

    while app.wait() {
        if let Some(msg) = receiver.recv() {
            // Browser rows are 1-indexed; vec index = row - 1.
            // "@F4" selects Courier so rows align with the Courier header.
            packets.lock().unwrap().push(msg.clone());
            let row = format!("@F4{}", msg.summary.replace('@', "@@"));
            packet_list.add(&row);
            if packet_list.value() == 0 {
                packet_list.bottom_line(packet_list.size());
            }
        }
    }
}
