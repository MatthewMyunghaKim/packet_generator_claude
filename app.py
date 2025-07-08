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
import glob

app = Flask(__name__)
app.secret_key = 'packet_generator_secret_key'

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def packet_capture_thread(interface, packet_queue, capture_filter, expected_count=1, max_duration=60, idle_timeout=5):
    """Capture packets on the specified interface with adaptive timeout"""
    try:
        logger.info(f"Starting packet capture on {interface}, expecting {expected_count} packets")
        logger.info(f"Capture filter: '{capture_filter}'")
        logger.info(f"Timeout: {idle_timeout}s from start OR after last packet")
        
        captured_packets = []
        start_time = time.time()
        last_packet_time = None  # No packets received yet
        
        def packet_handler(packet):
            nonlocal last_packet_time
            captured_packets.append(packet)
            packet_queue.put(packet)
            capture_time = time.time()
            last_packet_time = capture_time
            logger.info(f"📥 Captured packet {len(captured_packets)}/{expected_count} at {capture_time:.2f} - {packet.summary()}")
            
            # Stop capture if we have enough packets
            if len(captured_packets) >= expected_count:
                logger.info(f"🎯 Captured expected {expected_count} packets, stopping capture")
                return True  # Stop sniffing
            return False
        
        # Quick interface test - minimal overhead
        try:
            logger.info(f"🔧 Testing interface {interface}...")
            
            # Quick test - just verify interface works
            test_packets = sniff(iface=interface, timeout=0.5, count=0)
            logger.info(f"✓ Interface works: {len(test_packets)} packets in 0.5s")
            
        except Exception as test_error:
            logger.error(f"❌ Interface test failed: {test_error}")
            logger.error("Possible issues:")
            logger.error("  - Wrong interface name (use 'ip link show' to list)")
            logger.error("  - No root privileges (run with sudo)")
            logger.error("  - Interface is down (use 'ip link set <interface> up')")
        
        # Enhanced capture with continuous monitoring
        def capture_with_detailed_monitoring():
            total_batches = 0
            total_captured = 0
            capture_active = True
            
            logger.info("🔍 Starting enhanced packet capture with detailed monitoring")
            
            while capture_active:
                current_time = time.time()
                elapsed_since_start = current_time - start_time
                total_batches += 1
                
                # Quick timeout logic - 2 seconds for all scenarios
                if last_packet_time is None and elapsed_since_start > idle_timeout:
                    logger.info(f"⏰ Timeout: No packets for {idle_timeout}s from start")
                    break
                
                if last_packet_time is not None:
                    elapsed_since_last = current_time - last_packet_time
                    if elapsed_since_last > idle_timeout:
                        logger.info(f"⏰ Timeout: No packets for {idle_timeout}s after last packet")
                        break
                
                if elapsed_since_start > max_duration:
                    logger.info(f"⏰ Maximum duration ({max_duration}s) reached")
                    break
                
                # Capture with detailed monitoring
                try:
                    batch_start = time.time()
                    logger.info(f"📡 Batch {total_batches}: Capturing (elapsed: {elapsed_since_start:.1f}s, total so far: {total_captured})")
                    
                    # Use longer timeout and no filter for maximum capture
                    batch_packets = sniff(
                        iface=interface,
                        timeout=1.0,  # Longer batch timeout
                        promisc=True,  # Always use promiscuous mode
                        count=0
                    )
                    
                    batch_duration = time.time() - batch_start
                    batch_count = len(batch_packets)
                    total_captured += batch_count
                    
                    logger.info(f"📦 Batch {total_batches}: Captured {batch_count} packets in {batch_duration:.2f}s (total: {total_captured})")
                    
                    if batch_count > 0:
                        # Show sample of captured packets for debugging
                        for i, pkt in enumerate(batch_packets[:3]):  # Show first 3 packets
                            logger.info(f"   Sample {i+1}: {pkt.summary()}")
                        
                        if batch_count > 3:
                            logger.info(f"   ... and {batch_count - 3} more packets")
                    
                    # Process all captured packets immediately
                    packets_added_this_batch = 0
                    for packet in batch_packets:
                        if packet_handler(packet):
                            logger.info(f"🎯 Got all expected packets ({expected_count}), stopping capture")
                            return
                        packets_added_this_batch += 1
                    
                    logger.info(f"✅ Batch {total_batches}: Added {packets_added_this_batch} packets to queue")
                    
                    # If we haven't captured anything in several batches, show warning
                    if total_batches > 5 and total_captured == 0:
                        logger.warning(f"⚠️  No packets captured after {total_batches} batches - interface issue?")
                        
                        # Try a basic connectivity test
                        logger.info("🔧 Running interface diagnostic...")
                        test_packets = sniff(iface=interface, timeout=2.0, count=1)
                        if len(test_packets) > 0:
                            logger.info(f"✅ Interface can capture packets: {test_packets[0].summary()}")
                        else:
                            logger.error("❌ Interface appears unable to capture any packets")
                            
                except KeyboardInterrupt:
                    logger.info("🛑 Capture interrupted by user")
                    break
                except Exception as batch_error:
                    logger.error(f"❌ Batch {total_batches} error: {batch_error}")
                    time.sleep(0.1)
            
            logger.info(f"🏁 Capture finished: {total_batches} batches, {total_captured} total packets captured")
        
        # Run the enhanced capture
        capture_with_detailed_monitoring()
        
        elapsed_time = time.time() - start_time
        logger.info(f"Packet capture completed in {elapsed_time:.2f}s, captured {len(captured_packets)} packets")
        
    except Exception as e:
        logger.error(f"Error in packet capture: {str(e)}")
        import traceback
        logger.error(f"Traceback: {traceback.format_exc()}")

def cleanup_old_pcap_files():
    """Clean up old PCAP files, keeping only the latest sent and received files"""
    try:
        pcap_dir = "pcap_files"
        if not os.path.exists(pcap_dir):
            return
        
        # Get all PCAP files
        sent_files = glob.glob(os.path.join(pcap_dir, "sent_packets_*.pcap"))
        received_files = glob.glob(os.path.join(pcap_dir, "received_packets_*.pcap"))
        
        # Sort by modification time (newest first)
        sent_files.sort(key=os.path.getmtime, reverse=True)
        received_files.sort(key=os.path.getmtime, reverse=True)
        
        # Keep only the latest file of each type, delete the rest
        files_to_delete = sent_files[1:] + received_files[1:]  # Skip the first (newest) file
        
        deleted_count = 0
        for file_path in files_to_delete:
            try:
                os.remove(file_path)
                deleted_count += 1
                logger.info(f"🗑️  Deleted old PCAP file: {os.path.basename(file_path)}")
            except Exception as e:
                logger.warning(f"Could not delete {file_path}: {e}")
        
        if deleted_count > 0:
            logger.info(f"🧹 Cleaned up {deleted_count} old PCAP files")
        else:
            logger.info("🧹 No old PCAP files to clean up")
            
    except Exception as e:
        logger.error(f"Error during PCAP cleanup: {str(e)}")

def save_packets_to_pcap(packets, filename):
    """Save packets to a PCAP file"""
    try:
        # Create pcap directory if it doesn't exist
        pcap_dir = "pcap_files"
        if not os.path.exists(pcap_dir):
            os.makedirs(pcap_dir)
        
        filepath = os.path.join(pcap_dir, filename)
        # Force standard PCAP format for better Wireshark compatibility
        wrpcap(filepath, packets, linktype=1)  # DLT_EN10MB (Ethernet)
        logger.info(f"💾 Saved {len(packets)} packets to {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Error saving PCAP file: {str(e)}")
        return None

def simulate_packet_transmission(packet):
    """Return exact copy of packet for 1:1 testing"""
    try:
        # Return exact copy without any modifications for precise testing
        received_packet = packet.copy()
        
        # No modifications - exact 1:1 copy for testing purposes
        logger.debug("Returning exact packet copy (no simulation)")
        
        return received_packet
    except Exception as e:
        logger.error(f"Error copying packet: {str(e)}")
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
        
        for i, packet in enumerate(sent_packets):
            # Simulate packet transmission and reception
            received_packet = simulate_packet_transmission(packet)
            received_packets.append(received_packet)
            logger.info(f"📥 Mock received packet {i+1}/{len(sent_packets)}")
            
            # Add some delay to simulate network transmission
            time.sleep(0.005)  # Reduced to 5ms for faster processing
        
        # Add small final delay to ensure all processing is complete
        time.sleep(0.05)  # 50ms final delay
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
        return random.randint(min_size or 64, max_size or 10000)
    elif mode == 'incrementing':
        return min(max_size or 10000, (min_size or 64) + (packet_index * step))
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

def generate_protocol(mode, packet_index, base_protocol, ip_version=None):
    """Generate protocol based on mode"""
    if mode == 'Random':
        # Only allow L4 protocols if we have an IP layer
        if ip_version and ip_version != 'None':
            protocols = ['TCP', 'UDP', 'ICMP']
        else:
            protocols = ['None']  # Only None protocol allowed without IP layer
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
        if not base_payload or target_payload_size <= 0:
            return base_payload
        
        # Repeat the base pattern to fill target size
        pattern_length = len(base_payload)
        if pattern_length == 0:
            return b''
        
        # Calculate how many full repetitions we need
        full_repetitions = target_payload_size // pattern_length
        remaining_bytes = target_payload_size % pattern_length
        
        # Build the repeated payload
        repeated_payload = base_payload * full_repetitions
        
        # Add partial pattern if needed
        if remaining_bytes > 0:
            repeated_payload += base_payload[:remaining_bytes]
        
        return repeated_payload
    elif mode == 'random':
        # Generate random bytes to fill the target payload size
        return bytes([random.randint(0, 255) for _ in range(target_payload_size)])
    else:
        return base_payload

def packets_match(sent_packet, captured_packet):
    """Check if a captured packet matches a sent packet - more flexible matching"""
    try:
        # Extract IP addresses
        sent_src_ip = None
        sent_dst_ip = None  
        captured_src_ip = None
        captured_dst_ip = None
        
        if sent_packet.haslayer(IP):
            sent_src_ip = sent_packet[IP].src
            sent_dst_ip = sent_packet[IP].dst
        elif sent_packet.haslayer(IPv6):
            sent_src_ip = sent_packet[IPv6].src
            sent_dst_ip = sent_packet[IPv6].dst
            
        if captured_packet.haslayer(IP):
            captured_src_ip = captured_packet[IP].src
            captured_dst_ip = captured_packet[IP].dst
        elif captured_packet.haslayer(IPv6):
            captured_src_ip = captured_packet[IPv6].src
            captured_dst_ip = captured_packet[IPv6].dst
        
        # More flexible IP matching - check if any IP addresses are involved
        if sent_src_ip and sent_dst_ip and captured_src_ip and captured_dst_ip:
            # Check if this captured packet involves our test IPs
            our_ips = {sent_src_ip, sent_dst_ip}
            captured_ips = {captured_src_ip, captured_dst_ip}
            
            # If any of our test IPs appear in the captured packet, it's likely ours
            if our_ips.intersection(captured_ips):
                logger.debug(f"IP match: sent {sent_src_ip}→{sent_dst_ip}, captured {captured_src_ip}→{captured_dst_ip}")
                return True
        
        # Fallback: If no IP match, try protocol matching
        sent_proto = None
        captured_proto = None
        
        if sent_packet.haslayer(TCP):
            sent_proto = "TCP"
        elif sent_packet.haslayer(UDP):
            sent_proto = "UDP"
        elif sent_packet.haslayer(ICMP):
            sent_proto = "ICMP"
            
        if captured_packet.haslayer(TCP):
            captured_proto = "TCP"
        elif captured_packet.haslayer(UDP):
            captured_proto = "UDP"
        elif captured_packet.haslayer(ICMP):
            captured_proto = "ICMP"
        
        # If protocols match and we're capturing without strong IP filtering, include it
        if sent_proto and captured_proto and sent_proto == captured_proto:
            logger.debug(f"Protocol match: {sent_proto}")
            return True
        
        # If no IP layer, try MAC addresses (for Layer 2 tests)
        if sent_packet.haslayer(Ether) and captured_packet.haslayer(Ether):
            sent_src_mac = sent_packet[Ether].src
            sent_dst_mac = sent_packet[Ether].dst
            captured_src_mac = captured_packet[Ether].src
            captured_dst_mac = captured_packet[Ether].dst
            
            # Check if any of our test MACs appear
            our_macs = {sent_src_mac, sent_dst_mac}
            captured_macs = {captured_src_mac, captured_dst_mac}
            
            if our_macs.intersection(captured_macs):
                logger.debug(f"MAC match found")
                return True
        
        return False
    except Exception as e:
        logger.error(f"Error matching packets: {str(e)}")
        return False

def analyze_packet_mismatch(sent_packet, received_packet, packet_number):
    """Analyze detailed mismatch between two packets"""
    try:
        # Remove Ethernet layer for core packet comparison
        sent_without_eth = sent_packet.payload if sent_packet.haslayer(Ether) else sent_packet
        recv_without_eth = received_packet.payload if received_packet.haslayer(Ether) else received_packet
        
        sent_bytes = bytes(sent_without_eth)
        recv_bytes = bytes(recv_without_eth)
        
        analysis = {
            'packet_number': packet_number,
            'sent_length': len(sent_bytes),
            'received_length': len(recv_bytes),
            'first_diff_byte': None,
            'first_diff_offset': None,
            'sent_summary': sent_packet.summary(),
            'received_summary': received_packet.summary(),
            'hex_comparison': None
        }
        
        # Find first differing byte
        min_len = min(len(sent_bytes), len(recv_bytes))
        for i in range(min_len):
            if sent_bytes[i] != recv_bytes[i]:
                analysis['first_diff_offset'] = i
                analysis['first_diff_byte'] = {
                    'sent': f"0x{sent_bytes[i]:02x}",
                    'received': f"0x{recv_bytes[i]:02x}"
                }
                
                # Get hex context around the difference (±8 bytes)
                start = max(0, i - 8)
                end = min(len(sent_bytes), i + 9)
                
                sent_hex = ' '.join(f"{b:02x}" for b in sent_bytes[start:end])
                recv_hex = ' '.join(f"{b:02x}" for b in recv_bytes[start:end])
                
                # Mark the differing byte with markers
                diff_pos = i - start
                sent_hex_parts = sent_hex.split()
                recv_hex_parts = recv_hex.split()
                
                if diff_pos < len(sent_hex_parts):
                    sent_hex_parts[diff_pos] = f"[{sent_hex_parts[diff_pos]}]"
                if diff_pos < len(recv_hex_parts):
                    recv_hex_parts[diff_pos] = f"[{recv_hex_parts[diff_pos]}]"
                
                analysis['hex_comparison'] = {
                    'sent': ' '.join(sent_hex_parts),
                    'received': ' '.join(recv_hex_parts),
                    'offset_start': start
                }
                break
        
        # If no byte difference found but lengths differ
        if analysis['first_diff_offset'] is None and len(sent_bytes) != len(recv_bytes):
            analysis['first_diff_offset'] = min_len
            analysis['length_mismatch'] = True
        
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing packet mismatch: {str(e)}")
        return {'error': str(e)}

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
        
        # Validate protocol layer dependencies
        # Temporarily disabled for debugging
        # if ip_version == 'None' and protocol in ['TCP', 'UDP', 'ICMP']:
        #     return jsonify({'error': f'Cannot use {protocol} protocol without IP layer (IPv4/IPv6). Layer 4 protocols require Layer 3.'})
        
        # Payload generation parameters
        payload_mode = request.form.get('payload_mode', 'fixed')
        
        # Size generation parameters
        packet_size_mode = request.form.get('packet_size_mode', 'fixed')
        base_packet_length = int(request.form.get('packet_length', 64))
        size_min = int(request.form.get('size_min', 64))
        size_max = int(request.form.get('size_max', 10000))
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
            # Create capture filter - start with no filter for debugging
            # This helps identify if the issue is with filtering or capture itself
            if base_src_ip and base_dst_ip:
                # First try: no filter (capture everything for debugging)
                ip_filter = ""
                logger.info("Starting with NO FILTER to test basic capture capability")
                logger.info(f"Will look for packets with IPs: {base_src_ip} ↔ {base_dst_ip}")
            else:
                ip_filter = ""
                logger.info("Using no filter (capture all packets)")
            
            # Fast startup with minimal delays
            max_duration = 60
            idle_timeout = 2   # Quick timeout
            startup_delay = 2   # Much shorter startup
            logger.info(f"🚀 Fast mode: 2s startup, 2s timeout for {packet_count} packets")
            
            capture_thread = threading.Thread(
                target=packet_capture_thread,
                args=(recv_interface, packet_queue, ip_filter, packet_count, max_duration, idle_timeout)
            )
            capture_thread.start()
            
            # Minimal startup delay
            logger.info(f"⏳ Quick startup: waiting {startup_delay}s...")
            time.sleep(startup_delay)
            
            # Additional debugging for interface issues
            logger.info(f"Sending packets to interface: {send_interface}")
            logger.info(f"Receiving packets from interface: {recv_interface}")
            
            # Check if interfaces are the same (loopback scenario)
            if send_interface == recv_interface:
                logger.warning("Send and receive interfaces are the same - this may cause issues")
                logger.warning("Consider using different interfaces or test interfaces for better results")
        
        for i in range(packet_count):
            # Generate values for this packet
            current_ip_version = generate_ip_version(ip_version, i, ip_version)
            current_protocol = generate_protocol(protocol, i, protocol, current_ip_version)
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
                send_time = time.time()
                logger.info(f"📤 Sent packet {i+1}/{packet_count}: {current_src_ip}:{src_port} -> {current_dst_ip}:{dst_port} at {send_time:.2f}")
                
                # Adaptive delays to prevent race conditions
                if is_test_mode:
                    # For test mode, add slight delay to allow capture processing
                    time.sleep(0.05)  # 50ms delay for test mode
                else:
                    if packet_count == 1:
                        # Single packet - small delay to ensure capture
                        time.sleep(0.5)
                    else:
                        # Multiple packets - adaptive delay based on packet count
                        if packet_count <= 10:
                            time.sleep(0.2)  # 200ms for small batches
                        else:
                            time.sleep(0.1)  # 100ms for larger batches
                
            except Exception as e:
                logger.error(f"Failed to send packet {i+1}: {str(e)}")
                return jsonify({'error': f'Failed to send packet {i+1}: {str(e)}'})
        
        # Get received packets (real capture or mock)
        received_packets = []
        
        if is_test_mode:
            # Add final delay to ensure all packets are processed before mock capture
            logger.info(f"⏳ Waiting extra time for {packet_count} packets to be fully processed...")
            # Increased wait time for larger packet counts to prevent race conditions
            if packet_count <= 4:
                extra_wait = 0.1  # 100ms for small counts (1-4 packets)
            else:
                extra_wait = min(3.0, packet_count * 0.1)  # Max 3s, or 100ms per packet for 5+
            logger.info(f"⏳ Extra wait time: {extra_wait:.2f}s")
            time.sleep(extra_wait)
            
            # Use mock packet capture for test interfaces
            received_packets = mock_packet_capture(sent_packets, recv_interface, capture_filter)
        else:
            # Wait for capture thread to complete and get captured packets
            capture_thread.join()
            
            # Collect all captured packets
            all_captured = []
            queue_size = packet_queue.qsize()
            logger.info(f"📥 Collecting packets from queue (queue size: {queue_size})")
            
            packet_count_from_queue = 0
            while not packet_queue.empty():
                packet = packet_queue.get()
                all_captured.append(packet)
                packet_count_from_queue += 1
                
                # Log progress every 10 packets
                if packet_count_from_queue % 10 == 0:
                    logger.info(f"📥 Collected {packet_count_from_queue} packets from queue...")
            
            logger.info(f"📥 Finished collecting: {packet_count_from_queue} packets from queue")
            
            # For real interfaces, use all captured packets that match our criteria
            # Don't try to do 1:1 matching since packets can be duplicated, reordered, etc.
            
            if len(all_captured) > 0:
                logger.info(f"Raw captured packets: {len(all_captured)}")
                
                # Filter captured packets to only include those that match our test
                for i, captured_packet in enumerate(all_captured):
                    # Check if this packet matches any of our sent packet criteria
                    matches_our_test = False
                    
                    for sent_packet in sent_packets:
                        if packets_match(sent_packet, captured_packet):
                            matches_our_test = True
                            break
                    
                    if matches_our_test:
                        received_packets.append(captured_packet)
                        logger.debug(f"Added captured packet {i+1} to received list")
                    else:
                        logger.debug(f"Skipped captured packet {i+1} - doesn't match our test")
                
                logger.info(f"Filtered to {len(received_packets)} packets that match our test criteria")
            else:
                # If no filter was used, use all captured packets
                logger.warning("No capture filter was applied - this might include unrelated traffic")
                received_packets = all_captured
            
            logger.info(f"Final result: {len(all_captured)} total captured, {len(received_packets)} matching our test")
        
        logger.info(f"Received {len(received_packets)} packets for comparison")
        
        # Initialize comparison results list
        comparison_results = []
        
        # Analyze packet protocols for statistics
        def analyze_packet_protocols(packets, packet_type=""):
            stats = {
                'ipv4': 0,
                'ipv6': 0,
                'tcp': 0,
                'udp': 0,
                'icmp': 0,
                'other': 0
            }
            
            for packet in packets:
                # Count IP versions
                if packet.haslayer(IP):
                    stats['ipv4'] += 1
                elif packet.haslayer(IPv6):
                    stats['ipv6'] += 1
                else:
                    stats['other'] += 1
                
                # Count transport protocols
                if packet.haslayer(TCP):
                    stats['tcp'] += 1
                elif packet.haslayer(UDP):
                    stats['udp'] += 1
                elif packet.haslayer(ICMP):
                    stats['icmp'] += 1
                elif packet.haslayer(ICMPv6EchoRequest):
                    stats['icmp'] += 1
            
            return stats
        
        # Get protocol statistics for sent and received packets
        sent_protocol_stats = analyze_packet_protocols(sent_packets, "sent")
        received_protocol_stats = analyze_packet_protocols(received_packets, "received")
        
        # Calculate packet statistics
        packets_sent_count = len(sent_packets)
        packets_received_count = len(received_packets)
        packets_matched = 0
        packets_mismatched = 0
        packets_not_found = 0
        
        # Perform packet comparison and count results
        first_mismatch_details = None
        
        for i, sent_packet in enumerate(sent_packets):
            if i < len(received_packets):
                received_packet = received_packets[i]
                is_identical, comparison_msg = compare_packets(sent_packet, received_packet)
                
                if is_identical:
                    packets_matched += 1
                    comparison_results.append(f"Packet {i+1}: Received packet is identical with sent packet")
                else:
                    packets_mismatched += 1
                    comparison_results.append(f"Packet {i+1}: Packets are different - {comparison_msg}")
                    
                    # Capture details of the first mismatch for detailed analysis
                    if first_mismatch_details is None:
                        first_mismatch_details = analyze_packet_mismatch(sent_packet, received_packet, i+1)
            else:
                packets_not_found += 1
                comparison_results.append(f"Packet {i+1}: No corresponding received packet found")
        
        # Handle case where more packets were received than sent
        extra_received = 0
        if len(received_packets) > len(sent_packets):
            extra_received = len(received_packets) - len(sent_packets)
            for i in range(len(sent_packets), len(received_packets)):
                comparison_results.append(f"Extra received packet {i+1}: No corresponding sent packet")
        
        # Clean up old PCAP files before generating new ones
        cleanup_old_pcap_files()
        
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
        
        # Build success message with detailed statistics
        mode_text = " (Test Mode)" if is_test_mode else ""
        message = f'Successfully sent {packets_sent_count} packets, received {packets_received_count} packets{mode_text}'
        
        # Create packet statistics summary
        packet_stats = {
            'sent': packets_sent_count,
            'received': packets_received_count,
            'matched': packets_matched,
            'mismatched': packets_mismatched,
            'not_found': packets_not_found,
            'extra_received': extra_received if 'extra_received' in locals() else 0,
            'sent_protocols': sent_protocol_stats,
            'received_protocols': received_protocol_stats,
            'first_mismatch': first_mismatch_details
        }
        
        response_data = {
            'success': True, 
            'message': message,
            'packet_stats': packet_stats,
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
            return send_file(
                filepath, 
                as_attachment=True, 
                download_name=filename,
                mimetype='application/vnd.tcpdump.pcap'  # PCAP MIME type for Wireshark
            )
        else:
            return jsonify({'error': 'PCAP file not found'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to download PCAP file: {str(e)}'}), 500

@app.route('/open_pcap/<filename>')
def open_pcap(filename):
    """Open PCAP file directly (for Wireshark association)"""
    try:
        pcap_dir = "pcap_files"
        filepath = os.path.join(pcap_dir, filename)
        
        if os.path.exists(filepath):
            return send_file(
                filepath, 
                as_attachment=False,  # Open directly, don't download
                download_name=filename,
                mimetype='application/vnd.tcpdump.pcap'
            )
        else:
            return jsonify({'error': 'PCAP file not found'}), 404
    except Exception as e:
        return jsonify({'error': f'Failed to open PCAP file: {str(e)}'}), 500

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
    
    # Clean up old PCAP files on startup
    print("🧹 Cleaning up old PCAP files on startup...")
    cleanup_old_pcap_files()
    
    app.run(debug=True, host='0.0.0.0', port=9200)