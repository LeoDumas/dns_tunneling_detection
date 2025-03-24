use chrono::{DateTime, Local};
use pcap::Capture;
use std::collections::HashMap;
use std::fmt::Write as FmtWrite;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;

// DNS header and record types constants
const DNS_HEADER_SIZE: usize = 12;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

struct DnsQuery {
    domain: String,
    query_type: u16,
    query_class: u16,
    total_size: usize,
}

fn list_all_device() {
    for (i, device) in pcap::Device::list()
        .expect("Device lookup failed")
        .iter()
        .enumerate()
    {
        let device_name = device.desc.as_ref().unwrap_or(&device.name);
        let ipv4_addresses: Vec<_> = device
            .addresses
            .iter()
            .filter_map(|addr| {
                if let std::net::IpAddr::V4(ipv4) = addr.addr {
                    Some(ipv4.to_string())
                } else {
                    None
                }
            })
            .collect();
        let addr_display = if ipv4_addresses.is_empty() {
            String::from("no IPv4")
        } else {
            ipv4_addresses.join(", ")
        };
        println!("[{}] {} ({})", i, device_name, addr_display);
    }
}

// Hex dump returns a formatted string of the byte data.
fn hex_dump(data: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut output = String::new();

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        let _ = write!(&mut output, "{:08X}: ", i * BYTES_PER_LINE);
        for byte in chunk {
            let _ = write!(&mut output, "{:02X} ", byte);
        }
        if chunk.len() < BYTES_PER_LINE {
            for _ in 0..(BYTES_PER_LINE - chunk.len()) {
                let _ = write!(&mut output, "   ");
            }
        }
        let _ = write!(&mut output, "| ");
        for &byte in chunk {
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            let _ = write!(&mut output, "{}", ch);
        }
        let _ = writeln!(&mut output);
    }
    output
}

// Parse a dns query from the packet data.
fn parse_dns_packet(data: &[u8]) -> Option<DnsQuery> {
    if data.len() < 14 {
        return None;
    }
    let mut offset = 14;
    if data[12] != 0x08 || data[13] != 0x00 {
        return None;
    }
    if offset + 20 > data.len() {
        return None;
    }
    let ip_header_len = (data[offset] & 0x0F) as usize * 4;
    let protocol = data[offset + 9];
    offset += ip_header_len;
    if protocol != 17 || offset + 8 > data.len() {
        return None;
    }
    let src_port = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
    let dst_port = ((data[offset + 2] as u16) << 8) | data[offset + 3] as u16;
    if src_port != 53 && dst_port != 53 {
        return None;
    }
    offset += 8;
    if offset + DNS_HEADER_SIZE > data.len() {
        return None;
    }
    let _transaction_id = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
    let flags = ((data[offset + 2] as u16) << 8) | data[offset + 3] as u16;
    let questions = ((data[offset + 4] as u16) << 8) | data[offset + 5] as u16;
    offset += DNS_HEADER_SIZE;
    if (flags & 0x8000) != 0 || questions == 0 {
        return None;
    }
    let mut domain = String::new();
    let mut label_len = data[offset] as usize;
    offset += 1;
    while label_len > 0 {
        if offset + label_len > data.len() {
            return None;
        }
        if !domain.is_empty() {
            domain.push('.');
        }
        domain.push_str(
            std::str::from_utf8(&data[offset..offset + label_len]).unwrap_or("invalid-utf8"),
        );
        offset += label_len;
        if offset >= data.len() {
            return None;
        }
        label_len = data[offset] as usize;
        offset += 1;
    }
    if offset + 4 > data.len() {
        return None;
    }
    let query_type = ((data[offset] as u16) << 8) | data[offset + 1] as u16;
    let query_class = ((data[offset + 2] as u16) << 8) | data[offset + 3] as u16;
    Some(DnsQuery {
        domain,
        query_type,
        query_class,
        total_size: data.len(),
    })
}

// Adjusted heuristics for detecting dns tunneling.
fn is_dns_tunneling(query: &DnsQuery) -> (bool, Vec<String>) {
    let mut suspicious = false;
    let mut reasons = Vec::new();

    // Check for abonormally long domain names.
    if query.domain.len() > 50 {
        suspicious = true;
        reasons.push(format!(
            "Abnormally long domain name: {} chars",
            query.domain.len()
        ));
    }

    // Check for high entropy in the domain name.
    let entropy = calculate_entropy(&query.domain);
    if entropy > 4.0 {
        suspicious = true;
        reasons.push(format!("High entropy in domain name: {:.2}", entropy));
    }

    // Check for unusual character distribution.
    if has_unusual_char_distribution(&query.domain) {
        suspicious = true;
        reasons.push("Unusual character distribution in domain name".to_string());
    }

    // Allow A, AAAA, HTTPS (type 65) and TXT
    if query.query_type != TYPE_A && query.query_type != TYPE_AAAA && query.query_type != 65 {
        suspicious = true;
        reasons.push(format!("Unusual query type: {}", query.query_type));
    }

    if query.query_class != CLASS_IN {
        suspicious = true;
        reasons.push(format!(
            "Non-standard query class: {} (standard is {})",
            query.query_class, CLASS_IN
        ));
    }

    if query.total_size > 512 {
        suspicious = true;
        reasons.push(format!("Large DNS packet: {} bytes", query.total_size));
    }

    let subdomain_count = query.domain.matches('.').count();
    if subdomain_count > 5 {
        suspicious = true;
        reasons.push(format!("Excessive subdomain count: {}", subdomain_count));
    }

    (suspicious, reasons)
}

// Calculate Shannon entropy for a given string.
fn calculate_entropy(text: &str) -> f64 {
    let len = text.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut char_counts = HashMap::new();
    for c in text.chars() {
        *char_counts.entry(c).or_insert(0) += 1;
    }
    let mut entropy = 0.0;
    for &count in char_counts.values() {
        let probability = count as f64 / len;
        entropy -= probability * probability.log2();
    }
    entropy
}

// Allow hyphens and underscores in domain names.
fn has_unusual_char_distribution(domain: &str) -> bool {
    let digit_count = domain.chars().filter(|c| c.is_ascii_digit()).count();
    let special_count = domain
        .chars()
        .filter(|c| !c.is_ascii_alphanumeric() && *c != '.' && *c != '-' && *c != '_')
        .count();
    let len = domain.len();
    if len > 0 {
        let digit_ratio = digit_count as f64 / len as f64;
        let special_ratio = special_count as f64 / len as f64;
        // Flag if more than 40% digits or over 20% non standard special chars.
        digit_ratio > 0.4 || special_ratio > 0.2
    } else {
        false
    }
}

fn main() {
    let mut device_choice = String::new();
    let devices = pcap::Device::list().expect("Device lookup failed");

    list_all_device();
    println!("Enter the number of the device you want to capture: ");
    io::stdin()
        .read_line(&mut device_choice)
        .expect("Can't read line");

    let index: usize = match device_choice.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid input. Please enter a number.");
            return;
        }
    };

    if index >= devices.len() {
        println!(
            "Invalid device index. Please choose a number between 0 and {}",
            devices.len() - 1
        );
        return;
    }

    let device = &devices[index];
    let device_name = device.desc.as_ref().unwrap_or(&device.name);
    let ipv4_addresses: Vec<_> = device
        .addresses
        .iter()
        .filter_map(|addr| {
            if let std::net::IpAddr::V4(ipv4) = addr.addr {
                Some(ipv4.to_string())
            } else {
                None
            }
        })
        .collect();
    let addr_display = if ipv4_addresses.is_empty() {
        String::from("no IPv4")
    } else {
        ipv4_addresses.join(", ")
    };
    println!("Selected device: {} ({})", device_name, addr_display);

    let mut cap = Capture::from_device(device.clone())
        .unwrap()
        .promisc(true)
        .snaplen(5000)
        .immediate_mode(true)
        .open()
        .unwrap();

    println!("Starting DNS tunneling detection...");
    println!("Only suspicious DNS traffic will be logged to logs.txt");

    while let Ok(packet) = cap.next_packet() {
        if let Some(dns_query) = parse_dns_packet(&packet.data) {
            let (suspicious, reasons) = is_dns_tunneling(&dns_query);

            if suspicious {
                let timestamp_seconds = packet.header.ts.tv_sec as i64;
                let timestamp_micros = packet.header.ts.tv_usec;
                let dt_utc =
                    DateTime::from_timestamp(timestamp_seconds, (timestamp_micros * 1000) as u32)
                        .expect("Invalid timestamp");
                let dt = dt_utc.with_timezone(&Local);
                let formatted_time = dt.format("%d-%m-%Y %H:%M:%S%.3f").to_string();

                println!("DNS TUNNELING DETECTED");
                println!("Time: {}", formatted_time);
                println!("Domain: {}", dns_query.domain);
                println!("Detection reasons:");
                for reason in &reasons {
                    println!("  - {}", reason);
                }

                let hex_dump_data = hex_dump(&packet.data);
                println!("{}", hex_dump_data);

                let mut file = OpenOptions::new()
                    .append(true)
                    .create(true)
                    .open("logs.txt")
                    .expect("Failed to open or create logs.txt");

                file.write_all(b"DNS TUNNELING DETECTED \n")
                    .expect("Failed to write to logs.txt");
                file.write_all(formatted_time.as_bytes())
                    .expect("Failed to write timestamp to logs.txt");
                file.write_all(b"\n")
                    .expect("Failed to write newline to logs.txt");

                file.write_all(format!("Domain: {}\n", dns_query.domain).as_bytes())
                    .expect("Failed to write domain to logs.txt");
                file.write_all(b"Detection reasons:\n")
                    .expect("Failed to write to logs.txt");
                for reason in reasons {
                    file.write_all(format!("  - {}\n", reason).as_bytes())
                        .expect("Failed to write reasons to logs.txt");
                }

                file.write_all(hex_dump_data.as_bytes())
                    .expect("Failed to write hex dump to logs.txt");
                file.write_all(b"\n--------------------------------------------------\n")
                    .expect("Failed to write separator to logs.txt");
            }
        }
    }
}
