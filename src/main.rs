use pnet::datalink::{self, NetworkInterface, DataLinkSender};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet};
use pnet::packet::tcp::TcpPacket;
use std::env;

fn main() {
    let interface_name = env::args().nth(1).unwrap_or_else(|| "eth0".to_string());

    let interface = find_interface(&interface_name);
    println!("监听网卡: {}", interface_name);
    println!("MAC 地址: {:?}\n", interface.mac);

    let (mut tx, mut rx) = create_channel(&interface);
    start_capture(&mut tx, &mut rx);
}

fn find_interface(name: &str) -> NetworkInterface {
    let interfaces = datalink::interfaces();
    interfaces.into_iter()
        .find(|iface| iface.name == name)
        .expect(&format!("网卡 {} 不存在", name))
}

fn create_channel(interface: &NetworkInterface) -> (Box<dyn DataLinkSender>, Box<dyn std::io::Read>) {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("不支持的通道类型"),
        Err(e) => panic!("创建通道失败: {}", e),
    }
}

fn start_capture(tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn std::io::Read>) {
    loop {
        match rx.next() {
            Ok(packet) => {
                process_packet(tx, packet);
            }
            Err(e) => eprintln!("读取错误: {}", e),
        }
    }
}

fn process_packet(tx: &mut Box<dyn DataLinkSender>, packet: &[u8]) {
    let eth_packet = EthernetPacket::new(packet).unwrap();

    if eth_packet.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 {
        return;
    }

    let ip_packet = Ipv4Packet::new(eth_packet.payload())?;
    let src_ip = ip_packet.get_source();
    let dst_ip = ip_packet.get_destination();

    if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return;
    }

    let tcp_packet = TcpPacket::new(ip_packet.payload())?;
    let src_port = tcp_packet.get_source();
    let dst_port = tcp_packet.get_destination();

    println!("[TCP] {}:{} -> {}:{}",
        src_ip, src_port, dst_ip, dst_port);
}
