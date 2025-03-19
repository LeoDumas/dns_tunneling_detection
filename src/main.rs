use std::io;

use pcap::Capture;

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
        .open().unwrap();

    while let Ok(packet) = cap.next_packet() {
        println!("received packet! {:?}", packet);
    }
}
