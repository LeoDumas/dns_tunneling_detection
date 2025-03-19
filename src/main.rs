use std::io;
use pcap::Capture;
use chrono::prelude::*;

fn list_all_device() {
    for (i, device) in pcap::Device::list().expect("Device lookup failed").iter().enumerate() {
        // Get device name
        let device_name = device.desc.as_ref().unwrap_or(&device.name);
        // Extract ipv4 addresses if exists
        let ipv4_addresses: Vec<_> = device.addresses.iter()
            .filter_map(|addr| {
                if let std::net::IpAddr::V4(ipv4) = addr.addr {
                    Some(ipv4.to_string())
                } else {
                    None
                }
            })
            .collect();
        // Create a readable address display
        let addr_display = if ipv4_addresses.is_empty() {
            String::from("no IPv4")
        } else {
            ipv4_addresses.join(", ")
        };
        println!("[{}] {} ({})", i, device_name, addr_display);
    }
}

fn hex_dump(data: &[u8]) {
    const BYTES_PER_LINE: usize = 16;
    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Print offset
        print!("{:08X}: ", i * BYTES_PER_LINE);
        // Print hex bytes
        for byte in chunk {
            print!("{:02X} ", byte);
        }
        // Fill in spaces if last line is not full
        if chunk.len() < BYTES_PER_LINE {
            for _ in 0..(BYTES_PER_LINE - chunk.len()) {
                print!("   ");
            }
        }
        // Print the ASCII representation
        print!("| ");
        for &byte in chunk {
            // If the byte is printable, print it, otherwise print '.'
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            print!("{}", ch);
        }
        println!();
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

    // Parse the device index from user input
    let index: usize = match device_choice.trim().parse() {
        Ok(num) => num,
        Err(_) => {
            println!("Invalid input. Please enter a number.");
            return;
        }
    };

    // Check if the index is valid
    if index >= devices.len() {
        println!("Invalid device index. Please choose a number between 0 and {}", devices.len() - 1);
        return;
    }

    let device = &devices[index];
    // Get device name
    let device_name = device.desc.as_ref().unwrap_or(&device.name);
    // Extract ipv4 addresses
    let ipv4_addresses: Vec<_> = device.addresses.iter()
        .filter_map(|addr| {
            if let std::net::IpAddr::V4(ipv4) = addr.addr {
                Some(ipv4.to_string())
            } else {
                None
            }
        })
        .collect();
    // Create readable address display
    let addr_display = if ipv4_addresses.is_empty() {
        String::from("no IPv4")
    } else {
        ipv4_addresses.join(", ")
    };
    println!("Selected device: {} ({})", device_name, addr_display);

    let mut cap = Capture::from_device(device.clone()).unwrap()
        .promisc(true)
        .snaplen(5000)
        .immediate_mode(true)
        .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        // Packet { header: PacketHeader { ts: 1742414317.505640, caplen: 54, len: 54 }, data: [160, 181, 60, 131, 162, 172, 232, 156, 37, 124, 237, 152, 8, 0, 69, 0, 0, 40, 255, 233, 64, 0, 128, 6, 0, 0, 192, 168, 1, 17, 104, 208, 16, 91, 222, 234, 1, 187, 108, 56, 221, 163, 79, 243, 58, 146, 80, 17, 4, 1, 58, 255, 0, 0] }

        // Convert ts to date&time
        let timestamp_seconds = packet.header.ts.tv_sec as i64;
        let timestamp_micros = packet.header.ts.tv_usec;
        let dt_utc = DateTime::from_timestamp(timestamp_seconds, (timestamp_micros * 1000) as u32).unwrap();
        let dt = dt_utc.with_timezone(&Local);

        println!("Time: {}", dt.format("%d-%m-%Y %H:%M:%S%.3f"));
        hex_dump(&packet.data);
    }
}
