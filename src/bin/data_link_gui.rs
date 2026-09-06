use data_link_lib::{list_interfaces, run_capture};
use fltk::{
    app,
    button::Button,
    enums::Font,
    menu::Choice,
    prelude::*,
    text::{TextBuffer, TextDisplay},
    window::Window,
};
use fltk_theme::{color_themes, ColorTheme};
use std::sync::{Arc, Mutex};
use std::thread;

fn main() {
    let app = app::App::default().with_scheme(app::Scheme::Gtk);
    ColorTheme::new(color_themes::DARK_THEME).apply();

    let mut wind = Window::new(100, 100, 1200, 600, "Sniff This");

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
    let selected_protocol = Arc::new(Mutex::new(0));

    protocol_choices.set_callback({
        let selected_protocol = selected_protocol.clone();
        move |c| *selected_protocol.lock().unwrap() = c.value() as usize
    });

    start_button.set_callback({
        let running = running.clone();
        let interface_choice = interface_choice.clone();
        let frame_count = frame_count.clone();
        let selected_protocol = selected_protocol.clone();
        let sender = sender.clone();

        move |b| {
            let mut is_running = running.lock().unwrap();
            if *is_running {
                *is_running = false;
                b.set_label("Start");
            } else {
                let index = interface_choice.value() as usize;
                if interfaces.is_empty() {
                    eprintln!("No interfaces available.");
                    return;
                }
                *is_running = true;
                b.set_label("Stop");

                let interface = interfaces[index].clone();
                let running = running.clone();
                let frame_count = frame_count.clone();
                let selected_protocol = selected_protocol.clone();
                let sender = sender.clone();

                thread::spawn(move || {
                    run_capture(
                        interface,
                        running,
                        frame_count,
                        selected_protocol,
                        move |line| {
                            sender.send(line);
                        },
                    );
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
