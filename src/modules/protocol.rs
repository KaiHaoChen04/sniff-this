use pnet::packet::{
    arp::{ArpOperation, ArpPacket},
    ipv4::Ipv4Packet,
    vlan::VlanPacket,
    Packet,
};

#[derive(Debug, Clone)]
pub enum LinkLayerProtocol {
    ARP(String),
    VLAN(u16, String),
    PPP(String),
    Tunnel(String),
    Unknown(String),
    IPV4(String),
    IPV6(String),
}

pub fn parse_arp_packet(arp: &ArpPacket) -> String {
    let operation = match arp.get_operation() {
        ArpOperation(1) => "Request",
        ArpOperation(2) => "Reply",
        _ => "Unknown",
    };
    format!(
        "{} Sender: {}({}) -> Target: {}({})",
        operation,
        arp.get_sender_hw_addr(),
        arp.get_sender_proto_addr(),
        arp.get_target_hw_addr(),
        arp.get_target_proto_addr(),
    )
}

pub fn parse_vlan_packet(vlan: &VlanPacket) -> (u16, String) {
    let vlan_id = vlan.get_vlan_identifier();
    let pcp = vlan.get_priority_code_point().0;
    let dei = vlan.get_drop_eligible_indicator();
    (vlan_id, format!("PCP={}, DEI={}", pcp, dei))
}

pub fn parse_ipv4_packets(ipv4_packet: &Ipv4Packet) -> Vec<u8> {
    ipv4_packet.payload().to_vec()
}
