use pnet_datalink as datalink;

fn main() {
    println!("Available network interfaces:");
    println!("{:<30} {:<20} {:<15}", "Name", "MAC", "IP Addresses");
    println!("{:<30} {:<20} {:<15}", "----", "---", "------------");
    
    let interfaces = datalink::interfaces();
    let total_interfaces = interfaces.len();
    
    if interfaces.is_empty() {
        println!("No network interfaces found!");
    } else {
        // Use &interfaces to borrow it instead of consuming it
        for interface in &interfaces {
            let mac = interface.mac.map_or("N/A".to_string(), |mac| mac.to_string());
            let ip_addresses: Vec<String> = interface.ips
                .iter()
                .map(|ip| ip.to_string())
                .collect();
            
            println!("{:<30} {:<20} {}", 
                interface.name, 
                mac, 
                if ip_addresses.is_empty() { "None".to_string() } else { ip_addresses.join(", ") }
            );
        }
    }
    
    println!("\nTotal interfaces found: {}", total_interfaces);
}