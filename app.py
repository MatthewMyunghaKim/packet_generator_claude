#!/usr/bin/env python3
from flask import Flask, render_template, request, jsonify, flash
from scapy.all import *
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.layers.dns import DNSQR, DNSRR
try:
    from scapy.contrib.mpls import MPLS
except ImportError:
    # Fallback for older Scapy versions
    from scapy.layers.l2 import MPLS
import logging
import sys
import os
import threading
import time
from queue import Queue
import datetime
from flask import send_file
import subprocess
import platform
import random
import ipaddress

app = Flask(__name__)
app.secret_key = 'packet_generator_secret_key'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def packet_capture_thread(interface, packet_queue, capture_filter, duration=10):
    """Capture packets on the specified interface"""
    try:
        logger.info(f"Starting packet capture on {interface} for {duration} seconds")
        packets = sniff(iface=interface, timeout=duration, filter=capture_filter)
        for packet in packets:
            packet_queue.put(packet)
        logger.info(f"Captured {len(packets)} packets on {interface}")
    except Exception as e:
        logger.error(f"Error in packet capture: {str(e)}")

def save_packets_to_pcap(packets, filename):
    """Save packets to a PCAP file"""
    try:
        # Create pcap directory if it doesn't exist
        pcap_dir = "pcap_files"
        if not os.path.exists(pcap_dir):
            os.makedirs(pcap_dir)
        
        filepath = os.path.join(pcap_dir, filename)
        wrpcap(filepath, packets)
        logger.info(f"Saved {len(packets)} packets to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error saving PCAP file: {str(e)}")
        return None

def simulate_packet_transmission(packet):
    """Simulate packet transmission with some realistic modifications"""
    try:
        # Create a copy of the packet to simulate received packet
        received_packet = packet.copy()
        
        # Simulate network changes that might occur during transmission
        # 1. Change MAC addresses (as packets traverse different network segments)
        if received_packet.haslayer(Ether):
            # Simulate router MAC address changes
            received_packet[Ether].src = "aa:bb:cc:dd:ee:ff"
            received_packet[Ether].dst = "11:22:33:44:55:66"
        
        # 2. Simulate slight timing differences (already handled by packet creation time)
        
        # 3. Occasionally introduce small changes to simulate real network behavior
        import random
        if random.random() < 0.1:  # 10% chance of minor modification
            # Simulate TTL/hop count changes
            if received_packet.haslayer(IP):
                received_packet[IP].ttl = max(1, received_packet[IP].ttl - 1)
            elif received_packet.haslayer(IPv6):
                received_packet[IPv6].hlim = max(1, received_packet[IPv6].hlim - 1)
        
        return received_packet
    except Exception as e:
        logger.error(f"Error simulating packet transmission: {str(e)}")
        return packet

def mock_packet_send(packet, interface):
    """Mock packet sending for test interfaces"""
    try:
        logger.info(f"Mock sending packet on {interface}")
        return True
    except Exception as e:
        logger.error(f"Mock send error: {str(e)}")
        return False

def mock_packet_capture(sent_packets, interface, capture_filter):
    """Mock packet capture for test interfaces - simulates receiving the sent packets"""
    try:
        logger.info(f"Mock capturing packets on {interface}")
        received_packets = []
        
        for packet in sent_packets:
            # Simulate packet transmission and reception
            received_packet = simulate_packet_transmission(packet)
            received_packets.append(received_packet)
            
            # Add some delay to simulate network transmission
            time.sleep(0.01)
        
        logger.info(f"Mock captured {len(received_packets)} packets on {interface}")
        return received_packets
    except Exception as e:
        logger.error(f"Mock capture error: {str(e)}")
        return []

def generate_packet_size(mode, packet_index, base_size, min_size=None, max_size=None, step=1):
    """Generate packet size based on mode"""
    if mode == 'fixed':
        return base_size
    elif mode == 'random':
        return random.randint(min_size or 64, max_size or 1500)
    elif mode == 'incrementing':
        return min(max_size or 1500, (min_size or 64) + (packet_index * step))
    else:
        return base_size

def generate_ip_address(mode, packet_index, base_ip, ip_version='IPv4'):
    """Generate IP address based on mode"""
    if mode == 'fixed':
        # For fixed mode, if IP version doesn't match base IP, generate appropriate default
        if ip_version == 'IPv6' and '.' in base_ip:
            return "2001:db8::1"  # Default IPv6 address
        elif ip_version == 'IPv4' and ':' in base_ip:
            return "192.168.1.1"  # Default IPv4 address
        return base_ip
    elif mode == 'random':
        if ip_version == 'IPv4':
            return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
        else:  # IPv6
            # Generate a valid IPv6 address using the documentation prefix
            return f"2001:db8:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}::{random.randint(1, 65535):x}"
    elif mode == 'incrementing':
        try:
            # Check if base IP matches the current IP version
            if ip_version == 'IPv6' and '.' in base_ip:
                # Use default IPv6 base for incrementing
                base_ip = "2001:db8::1"
            elif ip_version == 'IPv4' and ':' in base_ip:
                # Use default IPv4 base for incrementing
                base_ip = "192.168.1.1"
            
            ip_obj = ipaddress.ip_address(base_ip)
            new_ip = ip_obj + packet_index
            return str(new_ip)
        except:
            # Fallback to generating random IP if increment fails
            if ip_version == 'IPv4':
                return f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            else:
                return f"2001:db8:{random.randint(0, 65535):x}:{random.randint(0, 65535):x}::{random.randint(1, 65535):x}"
    else:
        return base_ip

def generate_mac_address(mode, packet_index, base_mac):
    """Generate MAC address based on mode"""
    if mode == 'fixed':
        return base_mac
    elif mode == 'random':
        return ":".join([f"{random.randint(0, 255):02x}" for _ in range(6)])
    elif mode == 'incrementing':
        try:
            # Convert MAC to integer, increment, convert back
            mac_parts = base_mac.replace(':', '').replace('-', '')
            mac_int = int(mac_parts, 16)
            new_mac_int = (mac_int + packet_index) & 0xFFFFFFFFFFFF  # Keep within 48-bit range
            new_mac = f"{new_mac_int:012x}"
            return ":".join([new_mac[i:i+2] for i in range(0, 12, 2)])
        except:
            return base_mac
    else:
        return base_mac

def generate_protocol(mode, packet_index, base_protocol):
    """Generate protocol based on mode"""
    if mode == 'Random':
        protocols = ['TCP', 'UDP', 'ICMP']
        return random.choice(protocols)
    else:
        return base_protocol

def generate_ip_version(mode, packet_index, base_ip_version):
    """Generate IP version based on mode"""
    if mode == 'Random':
        versions = ['IPv4', 'IPv6']
        return random.choice(versions)
    else:
        return base_ip_version

def generate_payload(mode, base_payload, target_payload_size):
    """Generate payload based on mode"""
    if mode == 'fixed':
        return base_payload
    elif mode == 'random':
        # Generate random bytes to fill the target payload size
        return bytes([random.randint(0, 255) for _ in range(target_payload_size)])
    else:
        return base_payload

def compare_packets(sent_packet, received_packet):
    """Compare sent and received packets"""
    try:
        # Remove the Ethernet layer from both packets for comparison
        # as MAC addresses might change during routing
        sent_without_eth = sent_packet.payload if sent_packet.haslayer(Ether) else sent_packet
        recv_without_eth = received_packet.payload if received_packet.haslayer(Ether) else received_packet
        
        # Convert to bytes for comparison
        sent_bytes = bytes(sent_without_eth)
        recv_bytes = bytes(recv_without_eth)
        
        # Compare the packets
        if sent_bytes == recv_bytes:
            return True, "Packets are identical"
        else:
            # Find differences
            differences = []
            min_len = min(len(sent_bytes), len(recv_bytes))
            
            for i in range(min_len):
                if sent_bytes[i] != recv_bytes[i]:
                    differences.append(f"Byte {i}: sent={sent_bytes[i]:02x}, received={recv_bytes[i]:02x}")
            
            if len(sent_bytes) != len(recv_bytes):
                differences.append(f"Length difference: sent={len(sent_bytes)}, received={len(recv_bytes)}")
            
            return False, f"Packets differ: {'; '.join(differences[:5])}"  # Show first 5 differences
            
    except Exception as e:
        return False, f"Error comparing packets: {str(e)}"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate', methods=['POST'])
def generate_packets():
    try:
        protocol = request.form['protocol']
        ip_version = request.form['ip_version']
        packet_count = int(request.form['packet_count'])
        payload_data = request.form['payload_data']
        send_interface = request.form['send_interface']
        recv_interface = request.form['recv_interface']
        src_port = int(request.form.get('src_port', 0))
        dst_port = int(request.form.get('dst_port', 0))
        
        # Payload generation parameters
        payload_mode = request.form.get('payload_mode', 'fixed')
        
        # Size generation parameters
        packet_size_mode = request.form.get('packet_size_mode', 'fixed')
        base_packet_length = int(request.form.get('packet_length', 64))
        size_min = int(request.form.get('size_min', 64))
        size_max = int(request.form.get('size_max', 1500))
        size_step = int(request.form.get('size_step', 1))
        
        # MAC address generation parameters
        src_mac_mode = request.form.get('src_mac_mode', 'fixed')
        dst_mac_mode = request.form.get('dst_mac_mode', 'fixed')
        base_src_mac = request.form['src_mac']
        base_dst_mac = request.form['dst_mac']
        
        # IP address generation parameters
        src_ip_mode = request.form.get('src_ip_mode', 'fixed')
        dst_ip_mode = request.form.get('dst_ip_mode', 'fixed')
        base_src_ip = request.form['src_ip']
        base_dst_ip = request.form['dst_ip']
        
        # VLAN parameters
        vlan_count = int(request.form.get('vlan_count', 0))
        vlan_tags = []
        if vlan_count > 0:
            for i in range(1, vlan_count + 1):
                vlan_id = request.form.get(f'vlan{i}_id')
                vlan_priority = request.form.get(f'vlan{i}_priority', 0)
                if vlan_id:
                    vlan_tags.append({
                        'id': int(vlan_id),
                        'priority': int(vlan_priority)
                    })
        
        # MPLS parameters
        mpls_count = int(request.form.get('mpls_count', 0))
        mpls_labels = []
        if mpls_count > 0:
            for i in range(1, mpls_count + 1):
                mpls_label = request.form.get(f'mpls{i}_label')
                mpls_tc = request.form.get(f'mpls{i}_tc', 0)
                if mpls_label:
                    mpls_labels.append({
                        'label': int(mpls_label),
                        'tc': int(mpls_tc)
                    })

        if packet_count > 1000:
            return jsonify({'error': 'Packet count limited to 1000 for safety'})

        # Check if we're using test interfaces
        is_test_mode = (send_interface.startswith('test-') or recv_interface.startswith('test-'))
        
        # Create a filter for packet capture based on the sent packet characteristics
        capture_filter = f"host {base_src_ip} and host {base_dst_ip}"
        if protocol in ['TCP', 'UDP'] and src_port and dst_port:
            capture_filter += f" and port {dst_port}"
        
        packets_sent = []
        sent_packets = []  # Store sent packets for comparison
        comparison_results = []
        
        # For test mode, we'll use mock capture, for real interfaces use thread capture
        if not is_test_mode:
            # Start packet capture in a separate thread for real interfaces
            packet_queue = Queue()
            capture_thread = threading.Thread(
                target=packet_capture_thread,
                args=(recv_interface, packet_queue, capture_filter, 15)
            )
            capture_thread.start()
            
            # Give the capture thread time to start
            time.sleep(1)
        
        for i in range(packet_count):
            # Generate values for this packet
            current_protocol = generate_protocol(protocol, i, protocol)
            current_ip_version = generate_ip_version(ip_version, i, ip_version)
            current_packet_length = generate_packet_size(
                packet_size_mode, i, base_packet_length, size_min, size_max, size_step
            )
            current_src_mac = generate_mac_address(src_mac_mode, i, base_src_mac)
            current_dst_mac = generate_mac_address(dst_mac_mode, i, base_dst_mac)
            current_src_ip = generate_ip_address(src_ip_mode, i, base_src_ip, current_ip_version)
            current_dst_ip = generate_ip_address(dst_ip_mode, i, base_dst_ip, current_ip_version)
            
            # Start with Ethernet layer
            packet_layers = [Ether(src=current_src_mac, dst=current_dst_mac)]
            
            # Add VLAN layers if specified
            for vlan_tag in vlan_tags:
                vlan_layer = Dot1Q(vlan=vlan_tag['id'], prio=vlan_tag['priority'])
                packet_layers.append(vlan_layer)
            
            # Add MPLS labels if specified
            for j, mpls_label in enumerate(mpls_labels):
                # Set the bottom of stack bit for the last MPLS label
                s = 1 if j == len(mpls_labels) - 1 else 0
                mpls_layer = MPLS(label=mpls_label['label'], cos=mpls_label['tc'], s=s)
                packet_layers.append(mpls_layer)
            
            # Add IP layer (if not None)
            if current_ip_version != 'None':
                try:
                    if current_ip_version == 'IPv4':
                        # Validate IPv4 addresses
                        ipaddress.IPv4Address(current_src_ip)
                        ipaddress.IPv4Address(current_dst_ip)
                        ip_layer = IP(src=current_src_ip, dst=current_dst_ip)
                    else:
                        # Validate IPv6 addresses
                        ipaddress.IPv6Address(current_src_ip)
                        ipaddress.IPv6Address(current_dst_ip)
                        ip_layer = IPv6(src=current_src_ip, dst=current_dst_ip)
                    packet_layers.append(ip_layer)
                except Exception as e:
                    logger.error(f"IP address validation failed: src={current_src_ip}, dst={current_dst_ip}, version={current_ip_version}, error={e}")
                    return jsonify({'error': f'Invalid IP address: {current_src_ip} or {current_dst_ip} for {current_ip_version}'})
            
            # Add transport layer (if not None)
            if current_protocol != 'None':
                if current_protocol == 'TCP':
                    transport_layer = TCP(sport=src_port, dport=dst_port)
                elif current_protocol == 'UDP':
                    transport_layer = UDP(sport=src_port, dport=dst_port)
                elif current_protocol == 'ICMP':
                    if current_ip_version == 'IPv4':
                        transport_layer = ICMP()
                    elif current_ip_version == 'IPv6':
                        transport_layer = ICMPv6EchoRequest()
                    else:
                        # Can't have ICMP without IP layer
                        return jsonify({'error': 'ICMP protocol requires IP layer (IPv4 or IPv6)'})
                else:
                    return jsonify({'error': f'Unsupported protocol: {current_protocol}'})
                
                packet_layers.append(transport_layer)
            
            # Generate payload based on mode
            if payload_mode == 'fixed' and payload_data:
                # Handle hex format or text for base payload (only for fixed mode)
                if all(c in '0123456789ABCDEFabcdef ' for c in payload_data):
                    try:
                        # Parse hex bytes
                        hex_bytes = payload_data.replace(' ', '')
                        if len(hex_bytes) % 2 == 0:  # Even number of hex characters
                            base_payload = bytes.fromhex(hex_bytes)
                        else:
                            # Fallback to text encoding if not valid hex
                            base_payload = payload_data.encode('utf-8')
                    except ValueError:
                        # Fallback to text encoding if hex parsing fails
                        base_payload = payload_data.encode('utf-8')
                else:
                    # Treat as regular text
                    base_payload = payload_data.encode('utf-8')
            else:
                base_payload = b''
            
            # Build the packet by layering all components (without payload first)
            packet = packet_layers[0]
            for layer in packet_layers[1:]:
                packet = packet / layer
            
            # Calculate how much space is available for payload
            headers_size = len(packet)
            available_payload_space = current_packet_length - headers_size
            
            # Generate payload for this packet using the specified mode
            if available_payload_space > 0:
                payload = generate_payload(payload_mode, base_payload, available_payload_space)
                
                # Add payload to packet
                if payload:
                    packet = packet / payload
            else:
                # No space for payload
                payload = b''
            
            try:
                # Send packet (real or mock)
                if is_test_mode:
                    success = mock_packet_send(packet, send_interface)
                    if not success:
                        return jsonify({'error': f'Failed to mock send packet {i+1}'})
                else:
                    sendp(packet, iface=send_interface, verbose=False)
                
                sent_packets.append(packet)  # Store sent packet for comparison
                
                # Build packet description
                protocol_desc = current_protocol if current_protocol != 'None' else 'No L4'
                ip_desc = current_ip_version if current_ip_version != 'None' else 'No L3'
                packet_desc = f"Packet {i+1}: {protocol_desc}/{ip_desc} ({current_packet_length}B)"
                
                # Add source/destination info
                if current_ip_version != 'None':
                    packet_desc += f" {current_src_ip}→{current_dst_ip}"
                packet_desc += f" [{current_src_mac}→{current_dst_mac}]"
                
                if vlan_tags:
                    vlan_desc = ",".join([f"VLAN{tag['id']}" for tag in vlan_tags])
                    packet_desc += f" with {vlan_desc}"
                if mpls_labels:
                    mpls_desc = ",".join([f"MPLS{label['label']}" for label in mpls_labels])
                    packet_desc += f" with {mpls_desc}"
                
                if is_test_mode:
                    packet_desc += " sent (test mode)"
                else:
                    packet_desc += " sent"
                
                packets_sent.append(packet_desc)
                logger.info(f"Sent packet {i+1}: {current_src_ip}:{src_port} -> {current_dst_ip}:{dst_port}")
                
                # Small delay between packets to avoid overwhelming the capture
                time.sleep(0.1)
                
            except Exception as e:
                logger.error(f"Failed to send packet {i+1}: {str(e)}")
                return jsonify({'error': f'Failed to send packet {i+1}: {str(e)}'})
        
        # Get received packets (real capture or mock)
        received_packets = []
        
        if is_test_mode:
            # Use mock packet capture for test interfaces
            received_packets = mock_packet_capture(sent_packets, recv_interface, capture_filter)
        else:
            # Wait for capture thread to complete and get captured packets
            capture_thread.join()
            
            while not packet_queue.empty():
                received_packets.append(packet_queue.get())
        
        logger.info(f"Received {len(received_packets)} packets for comparison")
        
        # Perform packet comparison
        for i, sent_packet in enumerate(sent_packets):
            if i < len(received_packets):
                received_packet = received_packets[i]
                is_identical, comparison_msg = compare_packets(sent_packet, received_packet)
                
                if is_identical:
                    comparison_results.append(f"Packet {i+1}: Received packet is identical with sent packet")
                else:
                    comparison_results.append(f"Packet {i+1}: Packets are different - {comparison_msg}")
            else:
                comparison_results.append(f"Packet {i+1}: No corresponding received packet found")
        
        # Handle case where more packets were received than sent
        if len(received_packets) > len(sent_packets):
            for i in range(len(sent_packets), len(received_packets)):
                comparison_results.append(f"Extra received packet {i+1}: No corresponding sent packet")
        
        # Generate PCAP files
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sent_pcap_file = None
        received_pcap_file = None
        
        if sent_packets:
            sent_filename = f"sent_packets_{timestamp}.pcap"
            sent_pcap_file = save_packets_to_pcap(sent_packets, sent_filename)
        
        if received_packets:
            received_filename = f"received_packets_{timestamp}.pcap"
            received_pcap_file = save_packets_to_pcap(received_packets, received_filename)
        
        # Build success message
        mode_text = " (Test Mode)" if is_test_mode else ""
        message = f'Successfully sent {len(packets_sent)} packets, received {len(received_packets)} packets{mode_text}'
        
        response_data = {
            'success': True, 
            'message': message,
            'packets': packets_sent[:10],
            'comparison_results': comparison_results[:10],
            'test_mode': is_test_mode
        }
        
        # Add PCAP file information to response
        if sent_pcap_file:
            response_data['sent_pcap_file'] = os.path.basename(sent_pcap_file)
        if received_pcap_file:
            response_data['received_pcap_file'] = os.path.basename(received_pcap_file)
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error generating packets: {str(e)}")
        return jsonify({'error': f'Error generating packets: {str(e)}'})

@app.route('/download_pcap/<filename>')
def download_pcap(filename):
    """Download PCAP file"""
    try:
        pcap_dir = "pcap_files"
        filepath = os.path.join(pcap_dir, filename)
        
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'PCAP file not found'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to download PCAP file: {str(e)}'}), 500

@app.route('/open_wireshark/<filename>')
def open_wireshark(filename):
    """Open PCAP file in Wireshark"""
    try:
        pcap_dir = "pcap_files"
        filepath = os.path.join(pcap_dir, filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'PCAP file not found'}), 404
        
        # Get absolute path for Wireshark
        abs_filepath = os.path.abspath(filepath)
        
        # Determine Wireshark command based on platform
        system = platform.system()
        
        if system == "Darwin":  # macOS
            # Try different possible Wireshark locations on macOS
            wireshark_paths = [
                "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
                "/usr/local/bin/wireshark",
                "/opt/homebrew/bin/wireshark"
            ]
            
            wireshark_cmd = None
            for path in wireshark_paths:
                if os.path.exists(path):
                    wireshark_cmd = path
                    break
            
            if not wireshark_cmd:
                # Try using 'open' command as fallback
                try:
                    subprocess.Popen(['open', '-a', 'Wireshark', abs_filepath])
                    return jsonify({'success': True, 'message': f'Opened {filename} in Wireshark'})
                except:
                    return jsonify({'error': 'Wireshark not found. Please install Wireshark or ensure it is in your PATH.'}), 404
            else:
                subprocess.Popen([wireshark_cmd, abs_filepath])
                
        elif system == "Linux":
            # Linux
            subprocess.Popen(['wireshark', abs_filepath])
            
        elif system == "Windows":
            # Windows
            subprocess.Popen(['wireshark.exe', abs_filepath])
        else:
            return jsonify({'error': f'Unsupported platform: {system}'}), 400
        
        logger.info(f"Opened {filename} in Wireshark")
        return jsonify({'success': True, 'message': f'Opened {filename} in Wireshark'})
        
    except FileNotFoundError:
        return jsonify({'error': 'Wireshark not found. Please install Wireshark or ensure it is in your PATH.'}), 404
    except Exception as e:
        logger.error(f"Error opening Wireshark: {str(e)}")
        return jsonify({'error': f'Failed to open Wireshark: {str(e)}'}), 500

@app.route('/interfaces')
def get_interfaces():
    try:
        # Get real interfaces
        real_interfaces = get_if_list()
        
        # Add virtual test interfaces
        test_interfaces = [
            'test-send-interface',
            'test-receive-interface'
        ]
        
        # Combine real and test interfaces
        all_interfaces = real_interfaces + test_interfaces
        
        return jsonify({'interfaces': all_interfaces})
    except Exception as e:
        return jsonify({'error': f'Failed to get interfaces: {str(e)}'})

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Warning: This application requires root privileges to send packets.")
        print("Run with: sudo python3 app.py")
    
    app.run(debug=True, host='0.0.0.0', port=5000)