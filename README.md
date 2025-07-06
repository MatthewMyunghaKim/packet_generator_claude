# Network Packet Generator

A comprehensive web-based network packet generator built with Flask and Scapy, featuring advanced packet crafting, real-time analysis, and professional testing capabilities.

## 🚀 Features

### Core Packet Generation
- **Multi-Protocol Support**: TCP, UDP, ICMP, or None (Layer 2 only)
- **Dual IP Stack**: IPv4, IPv6, or None (Ethernet only)
- **Random Generation**: Random protocols and IP versions per packet
- **Advanced Layering**: Ethernet + VLAN + MPLS + IP + Transport + Payload

### Advanced Generation Modes
- **Packet Size**: Fixed, Random (min-max), or Incrementing (start + step)
- **IP Addresses**: Fixed, Random, or Incrementing for both source and destination
- **MAC Addresses**: Fixed, Random, or Incrementing for both source and destination
- **Flexible Configuration**: Mix and match different modes for comprehensive testing

### Network Layer Support
- **VLAN Tagging**: Up to 2 VLAN tags with configurable IDs and priorities
- **MPLS Labels**: Up to 6 MPLS labels with traffic class settings
- **Custom Payloads**: Hex format support (e.g., "00 FF AA BB") or plain text

### Analysis & Comparison
- **Real-time Comparison**: Byte-by-byte analysis of sent vs received packets
- **PCAP Generation**: Automatic creation of timestamped PCAP files
- **Wireshark Integration**: One-click opening in Wireshark for detailed analysis
- **Visual Results**: Color-coded comparison results with detailed difference reporting

### Test Mode
- **Virtual Interfaces**: Test without real network hardware or root privileges
- **Realistic Simulation**: Simulates MAC address changes and TTL decrements
- **Development Friendly**: Perfect for testing and development environments

## 📋 Requirements

- Python 3.7+
- macOS, Linux, or Windows
- Wireshark (optional, for PCAP analysis)

## 🛠️ Installation

1. **Clone or download the project files**
2. **Install dependencies:**
   ```bash
   pip3 install -r requirements.txt
   ```
3. **For macOS users**, if you encounter Xcode errors:
   ```bash
   xcode-select --install
   ```

## 🎯 Quick Start

### Basic Usage (No Root Required)
```bash
python3 app.py
```
Open your browser to `http://localhost:5000`

### Production Usage (Real Network Interfaces)
```bash
sudo python3 app.py
```

## 💻 Web Interface

### Default Configuration
- **Send Interface**: `test-send-interface`
- **Receive Interface**: `test-receive-interface`
- **Protocol**: None (No L4 Protocol)
- **IP Version**: None (No L3 Header)
- **Packet Size**: 64 bytes (fixed)
- **Payload**: `00 00 00 00` (hex format)

### Generation Modes

#### Packet Size Options
- **Fixed**: Single packet size (default: 64 bytes)
- **Random**: Random size between min and max values
- **Incrementing**: Start size with configurable increment step

#### Address Generation
- **Fixed**: Same address for all packets
- **Random**: Random addresses per packet
- **Incrementing**: Sequential address increment

#### Protocol Options
- **None**: Ethernet + VLAN/MPLS + Payload only
- **TCP/UDP/ICMP**: Standard transport protocols
- **Random**: Randomly select protocol per packet

## 📊 Understanding Results

### Packet Descriptions
```
Packet 1: TCP/IPv4 (128B) 192.168.1.100→192.168.1.1 [00:11:22:33:44:55→aa:bb:cc:dd:ee:ff] sent
```
- **Protocol/IP Version**: What was actually used
- **Size**: Actual packet size in bytes
- **IP Flow**: Source → Destination IP addresses
- **MAC Flow**: Source → Destination MAC addresses

### Comparison Results
- **✓ Green (Identical)**: Packets match (accounting for expected network changes)
- **✗ Red (Different)**: Packets differ beyond expected modifications
- **⚠ Orange**: Missing or extra packets

### Expected Differences (Normal)
In test mode, some differences are **intentionally simulated** to reflect real network behavior:
- **MAC Address Changes**: Routers modify MAC addresses between segments
- **TTL/Hop Limit Decrements**: Normal router behavior (10% chance)

## 📁 File Structure

```
packet-generator/
├── app.py                     # Flask backend application
├── requirements.txt           # Python dependencies
├── templates/
│   └── index.html            # Web interface
├── pcap_files/               # Auto-generated PCAP files
│   ├── sent_packets_*.pcap
│   └── received_packets_*.pcap
├── README.md                 # This file
└── packet_generator_development_log.md  # Detailed development log
```

## 🔧 Configuration Examples

### Load Testing
```
Protocol: Random
IP Version: Random
Packet Size: Random (64-1500 bytes)
IP Addresses: Random
MAC Addresses: Fixed
Packet Count: 1000
```

### Network Scanning
```
Protocol: TCP
IP Version: IPv4
Packet Size: Fixed (64 bytes)
Source IP: Fixed (192.168.1.100)
Destination IP: Incrementing (192.168.1.1)
Packet Count: 254
```

### Protocol Analysis
```
Protocol: Random
IP Version: Fixed (IPv4)
Packet Size: Incrementing (64 bytes, step 10)
IP Addresses: Fixed
Packet Count: 100
```

## 🎨 PCAP Analysis

### Download Options
- **📤 Download Sent Packets PCAP**: Contains all transmitted packets
- **📥 Download Received Packets PCAP**: Contains all captured packets

### Wireshark Integration
- **🦈 Open in Wireshark**: Direct launch with automatic file loading
- **Cross-platform**: Supports macOS, Linux, and Windows
- **Automatic Detection**: Finds Wireshark installation automatically

## 🐛 Troubleshooting

### Common Issues

**"MPLS is not defined" Error**
- Restart the application after installing dependencies

**Permission Denied (Real Interfaces)**
- Use `sudo python3 app.py` for real network interfaces
- Or use test interfaces (no sudo required)

**Wireshark Won't Open**
- Ensure Wireshark is installed and in your PATH
- macOS: Install from [wireshark.org](https://wireshark.org)

**DNS Resolution Errors**
- Switch to test interfaces for development
- Check IP address format compatibility

## 🚀 Advanced Usage

### Custom VLAN Configuration
```
VLAN Count: 2
VLAN 1 ID: 100 (Priority: 0)
VLAN 2 ID: 200 (Priority: 7)
```

### MPLS Label Stack
```
MPLS Count: 3
Label 1: 1000 (TC: 0)
Label 2: 2000 (TC: 4)
Label 3: 3000 (TC: 7)
```

### Hex Payload Format
```
Payload: "00 FF AA BB CC DD"
Result: Six bytes with values 0x00, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD
```

## 🔐 Security Considerations

- **Test Mode**: No network privileges required, safe for development
- **Production Mode**: Requires root privileges, use responsibly
- **Network Impact**: Be mindful of packet generation rate and destination
- **Legal Compliance**: Only use on networks you own or have permission to test

## 📚 Use Cases

### Network Development
- Protocol implementation testing
- Driver and firmware validation
- Network simulation and modeling

### Security Testing
- Penetration testing (authorized networks only)
- IDS/IPS testing and tuning
- Firewall rule validation

### Performance Testing
- Bandwidth and throughput testing
- Latency measurement setup
- Load testing preparation

### Education
- Network protocol learning
- Packet analysis training
- Cybersecurity education

## 🤝 Contributing

This project was developed collaboratively with Claude (Anthropic's AI assistant). The development process is fully documented in `packet_generator_development_log.md`.

### Development Guidelines
- Follow the existing code structure
- Add comprehensive error handling
- Update documentation for new features
- Test with both real and virtual interfaces

## 📄 License

This project is provided as-is for educational and testing purposes. Use responsibly and in accordance with local laws and regulations.

## 🙏 Acknowledgments

- **Scapy**: Powerful packet manipulation library
- **Flask**: Web framework for Python
- **Wireshark**: Network protocol analyzer
- **Claude AI**: Development assistance and guidance

## 📞 Support

For detailed development history and troubleshooting, see:
- `packet_generator_development_log.md` - Complete development documentation
- Scapy documentation: https://scapy.readthedocs.io/
- Flask documentation: https://flask.palletsprojects.com/

---

**Version**: 1.0.0  
**Last Updated**: 2024-07-06  
**Compatibility**: Python 3.7+, Cross-platform  
**Status**: Production Ready  

Happy packet crafting! 🎯📦