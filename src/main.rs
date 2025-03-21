use chrono::{DateTime, Local};
use pcap::Capture;
use std::fmt::Write as FmtWrite;
use std::fs::OpenOptions;
use std::io;
use std::io::Write;

fn list_all_device() {
    for (i, device) in pcap::Device::list()
        .expect("Device lookup failed")
        .iter()
        .enumerate()
    {
        // Get device name
        let device_name = device.desc.as_ref().unwrap_or(&device.name);
        // Extract ipv4 addresses if exists
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
        // Create a readable address display
        let addr_display = if ipv4_addresses.is_empty() {
            String::from("no IPv4")
        } else {
            ipv4_addresses.join(", ")
        };
        println!("[{}] {} ({})", i, device_name, addr_display);
    }
}

// Hex_dump returns a string with the formatted hex dump.
fn hex_dump(data: &[u8]) -> String {
    const BYTES_PER_LINE: usize = 16;
    let mut output = String::new();

    for (i, chunk) in data.chunks(BYTES_PER_LINE).enumerate() {
        // Print offset
        let _ = write!(&mut output, "{:08X}: ", i * BYTES_PER_LINE);
        // Print hex bytes
        for byte in chunk {
            let _ = write!(&mut output, "{:02X} ", byte);
        }
        // Fill in spaces if the last line is not full
        if chunk.len() < BYTES_PER_LINE {
            for _ in 0..(BYTES_PER_LINE - chunk.len()) {
                let _ = write!(&mut output, "   ");
            }
        }
        // Print the ASCII representation
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
        println!(
            "Invalid device index. Please choose a number between 0 and {}",
            devices.len() - 1
        );
        return;
    }

    let device = &devices[index];
    // Get device name
    let device_name = device.desc.as_ref().unwrap_or(&device.name);
    // Extract ipv4 addresses
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
    // Create readable address display
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

    while let Ok(packet) = cap.next_packet() {
        // Open the file in append mode, create it if it doesn't exist.
        let mut file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("logs.txt")
            .expect("Failed to open or create logs.txt");

        // Convert timestamp to date & time.
        let timestamp_seconds = packet.header.ts.tv_sec as i64;
        let timestamp_micros = packet.header.ts.tv_usec;
        let dt_utc = DateTime::from_timestamp(timestamp_seconds, (timestamp_micros * 1000) as u32)
            .expect("Invalid timestamp");
        let dt = dt_utc.with_timezone(&Local);
        let formatted_time = dt.format("%d-%m-%Y %H:%M:%S%.3f").to_string();

        println!("Time: {}", formatted_time);

        // Write the formatted timestamp to the file with a newline.
        file.write_all(formatted_time.as_bytes())
            .expect("Failed to write timestamp to logs.txt");
        file.write_all(b"\n")
            .expect("Failed to write newline to logs.txt");

        // Get the hex dump as a string and write it to the file.
        let hex_dump_data = hex_dump(&packet.data);
        println!("{}", hex_dump_data);
        file.write_all(hex_dump_data.as_bytes())
            .expect("Failed to write hex dump to logs.txt");
        file.write_all(b"\n")
            .expect("Failed to write newline to logs.txt");
    }
}
