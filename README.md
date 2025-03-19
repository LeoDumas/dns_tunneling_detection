# DNS Tunneling Detection

A Rust application that uses the pcap library to detect DNS tunneling attacks in network traffic.

## Installation

### Prerequisites

Before building the application, you need to install the pcap library dependencies for your operating system:

#### Windows

- Install [Npcap](https://npcap.com/#download)
- Download the [Npcap SDK](https://npcap.com/#download)
- Add the SDK's `/Lib` or `/Lib/x64` folder to your LIB environment variable

#### Linux

Install the libraries and header files for the libpcap library:

- On Debian-based distributions:
  ```
  sudo apt-get install libpcap-dev
  ```

- On Fedora:
  ```
  sudo dnf install libpcap-devel
  ```

**Note**: If not running as root, you need to set capabilities:
```
sudo setcap cap_net_raw,cap_net_admin=eip path/to/dns_tunneling_detection
```

#### macOS

libpcap should be installed on macOS by default.

[pcap Crates](https://crates.io/crates/pcap)