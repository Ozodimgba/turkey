use clap::Parser;
use pnet_datalink::{self as datalink, Config, NetworkInterface};
use pnet_packet::ethernet::{EtherTypes, EthernetPacket};
use pnet_packet::ip::IpNextHeaderProtocols;
use pnet_packet::ipv4::Ipv4Packet;
use pnet_packet::ipv6::Ipv6Packet;
use pnet_packet::tcp::TcpPacket;
use pnet_packet::udp::UdpPacket;
use pnet_packet::Packet;
use std::cmp::min;
use std::net::IpAddr;
use std::io::{self, Write};
use std::process;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Network interface to capture packets on
    #[arg(short, long)]
    interface: Option<String>,

    /// Maximum number of packets to capture (0 for unlimited)
    #[arg(short, long, default_value_t = 0)]
    count: usize,

    /// Filter packets by protocol (tcp, udp, all)
    #[arg(short, long, default_value = "all")]
    protocol: String,

    /// Just list available interfaces
    #[arg(short, long)]
    list: bool,
}

fn main() {
    let args = Args::parse();
    
    // Get all network interfaces
    let interfaces = datalink::interfaces();
    
    // If the list flag is provided, just list interfaces and exit
    if args.list {
        list_interfaces(&interfaces);
        return;
    }
    
    // Select an interface - either the one provided by the user or prompt for selection
    let interface = match &args.interface {
        Some(name) => {
            match interfaces.iter().find(|iface| iface.name == *name) {
                Some(iface) => iface.clone(),
                None => {
                    eprintln!("Error: Interface '{}' not found.", name);
                    eprintln!("Available interfaces:");
                    list_interfaces(&interfaces);
                    process::exit(1);
                }
            }
        },
        None => {
            if interfaces.is_empty() {
                eprintln!("No network interfaces found!");
                process::exit(1);
            }
            
            // If no interface specified, use the first non-loopback interface or prompt the user
            match interfaces.iter().find(|iface| !iface.is_loopback() && !iface.name.contains("tunl")) {
                Some(iface) => {
                    println!("No interface specified. Using {}.", iface.name);
                    iface.clone()
                },
                None => {
                    eprintln!("No suitable interface found automatically.");
                    list_interfaces(&interfaces);
                    eprintln!("Please specify an interface with --interface.");
                    process::exit(1);
                }
            }
        }
    };

    println!("Starting packet capture on interface: {}", interface.name);
    println!("Protocol filter: {}", args.protocol);
    
    // Try different configurations for creating a channel
    let configs = vec![
        Config::default(),
        Config {
            read_timeout: Some(std::time::Duration::from_secs(1)),
            ..Default::default()
        },
        Config {
            promiscuous: false,
            ..Default::default()
        }
    ];
    
    let mut channel = None;
    
    for config in configs {
        match datalink::channel(&interface, config) {
            Ok(datalink::Channel::Ethernet(tx, rx)) => {
                channel = Some((tx, rx));
                break;
            },
            Ok(_) => {
                eprintln!("Unhandled channel type. Trying another config");
                continue;
            },
            Err(e) => {
                eprintln!("Error creating channel with config: {}", e);
                continue;
            }
        }
    }
    
    let (_tx, mut rx) = match channel {
        Some(c) => c,
        None => {
            eprintln!("Failed to create channel on interface: {}", interface.name);
            process::exit(1);
        }
    };

    let mut packet_count = 0;

    
    println!("Capturing packets... hehehe");
    loop {
        match rx.next() {
            Ok(packet) => {
                println!("Raw packet bytes ({}): {:02X?}", packet.len(), &packet[0..min(16, packet.len())]);

                if let Some(ethernet) = EthernetPacket::new(packet) {
                    // Process the packet
                    match process_packet(&ethernet, &args.protocol) {
                        Some(packet_info) => {
                            println!("{}", packet_info);
                            packet_count += 1;
                            
                            // Check if we've reached the packet count limit
                            if args.count > 0 && packet_count >= args.count {
                                println!("Reached packet count limit of {}. Exiting.", args.count);
                                break;
                            }
                        },
                        None => continue,
                    }
                }
            }
            Err(e) => {
                eprintln!("Error receiving packet: {}", e);
                // Don't break on error, try to continue
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }
    
    println!("Captured {} packets.", packet_count);
}

fn list_interfaces(interfaces: &[NetworkInterface]) {
    println!("Available network interfaces:");
    println!("{:<20} {:<20} {:<15} {:<10}", "Name", "MAC", "IP Addresses", "Status");
    println!("{:<20} {:<20} {:<15} {:<10}", "----", "---", "------------", "------");
    
    for interface in interfaces {
        let mac = interface.mac.map_or("N/A".to_string(), |mac| mac.to_string());
        let ip_addresses: Vec<String> = interface.ips
            .iter()
            .map(|ip| ip.to_string())
            .collect();
        
        println!("{:<20} {:<20} {:<15} {:<10}", 
            interface.name, 
            mac, 
            if ip_addresses.is_empty() { "None".to_string() } else { ip_addresses.join(", ") },
            if interface.is_up() { "Up" } else { "Down" }
        );
    }
    
    println!("\nTotal interfaces found: {}", interfaces.len());
}

fn process_packet(ethernet: &EthernetPacket, protocol_filter: &str) -> Option<String> {
    let mut packet_info = format!(
        "Ethernet Frame: {} -> {} (EtherType: {:?})",
        ethernet.get_source(),
        ethernet.get_destination(),
        ethernet.get_ethertype()
    );

    match ethernet.get_ethertype() {
        EtherTypes::Ipv4 => {
            if let Some(ipv4_packet) = Ipv4Packet::new(ethernet.payload()) {
                let source = IpAddr::V4(ipv4_packet.get_source());
                let destination = IpAddr::V4(ipv4_packet.get_destination());
                
                packet_info.push_str(&format!(
                    "\n  IPv4: {} -> {} (Protocol: {:?}, TTL: {})",
                    source,
                    destination,
                    ipv4_packet.get_next_level_protocol(),
                    ipv4_packet.get_ttl()
                ));
                
                match ipv4_packet.get_next_level_protocol() {
                    IpNextHeaderProtocols::Tcp => {
                        if protocol_filter != "all" && protocol_filter != "tcp" {
                            return None;
                        }
                        
                        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                            packet_info.push_str(&format!(
                                "\n    TCP: {}:{} -> {}:{} (Flags: {}{}{}{}{}, Seq: {}, Ack: {})",
                                source,
                                tcp_packet.get_source(),
                                destination,
                                tcp_packet.get_destination(),
                                if tcp_packet.get_flags() & 0b00010000 != 0 { "A" } else { "" },
                                if tcp_packet.get_flags() & 0b00000010 != 0 { "S" } else { "" },
                                if tcp_packet.get_flags() & 0b00000001 != 0 { "F" } else { "" },
                                if tcp_packet.get_flags() & 0b00000100 != 0 { "R" } else { "" },
                                if tcp_packet.get_flags() & 0b00100000 != 0 { "U" } else { "" },
                                tcp_packet.get_sequence(),
                                tcp_packet.get_acknowledgement()
                            ));
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        if protocol_filter != "all" && protocol_filter != "udp" {
                            return None;
                        }
                        
                        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
                            packet_info.push_str(&format!(
                                "\n    UDP: {}:{} -> {}:{} (Length: {})",
                                source,
                                udp_packet.get_source(),
                                destination,
                                udp_packet.get_destination(),
                                udp_packet.get_length()
                            ));
                        }
                    },
                    _ => {
                        packet_info.push_str("\n    Other IP protocol");
                    }
                }
            }
        },
        EtherTypes::Ipv6 => {
            if let Some(ipv6_packet) = Ipv6Packet::new(ethernet.payload()) {
                let source = IpAddr::V6(ipv6_packet.get_source());
                let destination = IpAddr::V6(ipv6_packet.get_destination());
                
                packet_info.push_str(&format!(
                    "\n  IPv6: {} -> {} (Next Header: {:?})",
                    source,
                    destination,
                    ipv6_packet.get_next_header()
                ));
                
                match ipv6_packet.get_next_header() {
                    IpNextHeaderProtocols::Tcp => {
                        if protocol_filter != "all" && protocol_filter != "tcp" {
                            return None;
                        }
                        
                        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                            packet_info.push_str(&format!(
                                "\n    TCP: {}:{} -> {}:{} (Flags: {}{}{}{}{}, Seq: {}, Ack: {})",
                                source,
                                tcp_packet.get_source(),
                                destination,
                                tcp_packet.get_destination(),
                                if tcp_packet.get_flags() & 0b00010000 != 0 { "A" } else { "" },
                                if tcp_packet.get_flags() & 0b00000010 != 0 { "S" } else { "" },
                                if tcp_packet.get_flags() & 0b00000001 != 0 { "F" } else { "" },
                                if tcp_packet.get_flags() & 0b00000100 != 0 { "R" } else { "" },
                                if tcp_packet.get_flags() & 0b00100000 != 0 { "U" } else { "" },
                                tcp_packet.get_sequence(),
                                tcp_packet.get_acknowledgement()
                            ));
                        }
                    },
                    IpNextHeaderProtocols::Udp => {
                        if protocol_filter != "all" && protocol_filter != "udp" {
                            return None;
                        }
                        
                        if let Some(udp_packet) = UdpPacket::new(ipv6_packet.payload()) {
                            packet_info.push_str(&format!(
                                "\n    UDP: {}:{} -> {}:{} (Length: {})",
                                source,
                                udp_packet.get_source(),
                                destination,
                                udp_packet.get_destination(),
                                udp_packet.get_length()
                            ));
                        }
                    },
                    _ => {
                        packet_info.push_str("\n    Other IPv6 next header");
                    }
                }
            }
        },
        _ => {
            packet_info.push_str(&format!("\n  Unsupported EtherType: {:?}", ethernet.get_ethertype()));
        }
    }
    
    Some(packet_info)
}