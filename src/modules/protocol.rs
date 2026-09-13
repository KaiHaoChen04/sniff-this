use pnet::packet::{
    arp::{ArpOperation, ArpPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    vlan::VlanPacket,
    Packet,
};
use std::net::IpAddr;

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

trait IpPacketAddress {
    fn src_addr(&self) -> IpAddr;
    fn dest_addr(&self) -> IpAddr;
}

impl IpPacketAddress for Ipv4Packet<'_> {
    fn src_addr(&self) -> IpAddr {
        IpAddr::V4(self.get_source())
    }
    fn dest_addr(&self) -> IpAddr {
        IpAddr::V4(self.get_destination())
    }
}

impl IpPacketAddress for Ipv6Packet<'_> {
    fn src_addr(&self) -> IpAddr {
        IpAddr::V6(self.get_source())
    }
    fn dest_addr(&self) -> IpAddr {
        IpAddr::V6(self.get_destination())
    }
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

pub fn parse_ip_packets<T>(packet: T) -> String
where
    T: Packet + IpPacketAddress,
{
    let payload_hex: String = packet
        .payload()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect();

    format!(
        "Source: {}  Dest: {} Payload ({})",
        packet.src_addr(),
        packet.dest_addr(),
        payload_hex
    )
}
