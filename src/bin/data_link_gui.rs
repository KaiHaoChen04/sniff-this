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

fn main() {}
