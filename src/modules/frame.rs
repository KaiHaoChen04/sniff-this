use crate::modules::protocol::LinkLayerProtocol;

pub struct LinkLayerFrame {
    pub timestamp: f64,
    pub source_mac: String,
    pub dest_mac: String,
    pub protocol: LinkLayerProtocol,
    pub length: usize,
    pub hex_detail: String,
}

pub fn format_frame(frame: &LinkLayerFrame, count: usize) -> String {
    let protocol_string = match &frame.protocol {
        LinkLayerProtocol::ARP(d) => format!("ARP     {}", d),
        LinkLayerProtocol::VLAN(id, d) => format!("VLAN     {}{}", id, d),
        LinkLayerProtocol::PPP(d) => format!("PPP      {}", d),
        LinkLayerProtocol::Tunnel(d) => format!("Tunnel     {}", d),
        LinkLayerProtocol::IPV4(d) => format!("IPV4     {}", d),
        LinkLayerProtocol::IPV6(d) => format!("IPV6     {}", d),
        LinkLayerProtocol::Unknown(d) => format!("Unknown    {}", d),
    };

    format!(
        "{:>6} {:>12.2} {:>18} -> {:>18} {:>4} {}\n",
        count, frame.timestamp, frame.source_mac, frame.dest_mac, frame.length, protocol_string,
    )
}

/// Multi-line detail shown in the bottom pane when a row is clicked.
/// Keeps the long hex payload out of the one-line packet list.
pub fn format_detail(frame: &LinkLayerFrame, count: usize) -> String {
    let protocol_string = match &frame.protocol {
        LinkLayerProtocol::ARP(d) => format!("ARP {}", d),
        LinkLayerProtocol::VLAN(id, d) => format!("VLAN id={} {}", id, d),
        LinkLayerProtocol::PPP(d) => format!("PPP {}", d),
        LinkLayerProtocol::Tunnel(d) => format!("Tunnel {}", d),
        LinkLayerProtocol::IPV4(d) => format!("IPV4 {}", d),
        LinkLayerProtocol::IPV6(d) => format!("IPV6 {}", d),
        LinkLayerProtocol::Unknown(d) => format!("Unknown {}", d),
    };

    format!(
        "Frame {}: {:.6}s  {} -> {}  len={}  {}\nHex payload ({} bytes):\n{}",
        count,
        frame.timestamp,
        frame.source_mac,
        frame.dest_mac,
        frame.length,
        protocol_string,
        frame.length,
        frame.hex_detail,
    )
}
