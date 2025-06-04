import subprocess
import time
import datetime
import os
import sys
import threading
from scapy.all import sniff, IP, TCP
import ipaddress
import logging
from functools import partial


# to check if the IP Address is blocked, we can use sudo iptables -L command to check if the IP Address is blocked or not.

# Set up logging
logging.basicConfig(filename='ids.log', level=logging.INFO, format='%(asctime)s — %(message)s', datefmt='%d-%m-%y %H:%M:%S')

running = False
blocked_ips = set()
port_scan_tracker = {}
os_fingerprint_tracker = {}

def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False

def packet_callback(packet, flag):
    if not running:
        return

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "Unknown"
        src_port = "-"
        dst_port = "-"
        flags = "-"

        if TCP in packet:
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            flags = get_tcp_flags(packet[TCP])
            
            if not is_local_ip(src_ip) and dst_ip.startswith('192.168.'):
                detect_port_scanning(src_ip, dst_port)
                detect_os_fingerprinting(src_ip, flags)
        
        # Log packet info for monitoring
        if flag:
            print(f"Time: {datetime.datetime.now().strftime('%H:%M:%S')}, "
              f"Src: {src_ip}:{src_port}, Dst: {dst_ip}:{dst_port}, "
              f"Protocol: {protocol}, Flags: {flags}")

def is_local_ip(ip):
    return ip == "127.0.0.1" or ip.startswith("192.168.")

def get_tcp_flags(tcp_packet):
    flags = []
    if tcp_packet.flags & 0x01:
        flags.append("FIN")
    if tcp_packet.flags & 0x02:
        flags.append("SYN")
    if tcp_packet.flags & 0x04:
        flags.append("RST")
    if tcp_packet.flags & 0x08:
        flags.append("PSH")
    if tcp_packet.flags & 0x10:
        flags.append("ACK")
    if tcp_packet.flags & 0x20:
        flags.append("URG")
    return "+".join(flags) if flags else "None"

def detect_port_scanning(src_ip, dst_port):
    current_time = time.time()
    if src_ip in blocked_ips:
        return
    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = {}
    port_scan_tracker[src_ip][current_time] = dst_port
    recent_times = [t for t in port_scan_tracker[src_ip].keys() if current_time - t <= 15]
    recent_ports = [port_scan_tracker[src_ip][t] for t in recent_times]

    for old_time in list(port_scan_tracker[src_ip].keys()):
        if current_time - old_time > 15:
            del port_scan_tracker[src_ip][old_time]
    
    # 1. Multiple Port Scanning Detection
    unique_ports = set(recent_ports)
    if len(unique_ports) >= 6:
        time_span = int(current_time - min(recent_times))
        log_intrusion("Multiple Port Scanning", src_ip, list(unique_ports), time_span)
        block_ip(src_ip)        
        port_scan_tracker.pop(src_ip, None)
        return
    
    # 2. Sequential Port Scanning Detection
    if len(recent_ports) >= 4:
        sorted_ports = sorted(recent_ports)
        for i in range(len(sorted_ports) - 3):
            if (sorted_ports[i+1] == sorted_ports[i] + 1 and 
                sorted_ports[i+2] == sorted_ports[i] + 2 and 
                sorted_ports[i+3] == sorted_ports[i] + 3):
                time_span = int(current_time - min(recent_times))
                log_intrusion("Sequential Port Scanning", src_ip, sorted_ports, time_span)
                block_ip(src_ip)
                port_scan_tracker.pop(src_ip, None)
                return



def detect_os_fingerprinting(src_ip, flags):
    if not flags or src_ip in blocked_ips:
        return
    current_time = time.time()
    if src_ip not in os_fingerprint_tracker:
        os_fingerprint_tracker[src_ip] = {}
    os_fingerprint_tracker[src_ip][current_time] = flags
    
    recent_times = [t for t in os_fingerprint_tracker[src_ip].keys() if current_time - t <= 20]
    recent_flags = [os_fingerprint_tracker[src_ip][t] for t in recent_times]
    for old_time in list(os_fingerprint_tracker[src_ip].keys()):
        if current_time - old_time > 20:
            del os_fingerprint_tracker[src_ip][old_time]
    
    # Detect OS fingerprinting by unique flag combinations
    unique_flags = set(recent_flags)
    if len(unique_flags) >= 5:
        time_span = int(current_time - min(recent_times))
        log_intrusion("OS Fingerprinting", src_ip, list(unique_flags), time_span)
        block_ip(src_ip)
        os_fingerprint_tracker.pop(src_ip, None)

def log_intrusion(intrusion_type, attacker_ip, target_details, time_span):
    print(f"{attacker_ip = }")
    if isinstance(target_details, list):
        if isinstance(target_details[0], int):
            details_str = ", ".join(str(p) for p in sorted(target_details))
        else:
            details_str = ", ".join(target_details)
    else:
        details_str = str(target_details)
    log_message = f"{intrusion_type} — {attacker_ip} — {details_str} — {time_span}s"
    logging.info(log_message)
    print(f"ALERT: {log_message}")

def block_ip(ip):
    if ip in blocked_ips:
        return
        
    try:
        # Check if running as root (required for iptables)
        if os.geteuid() == 0:
            subprocess.run(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"Blocked IP: {ip}")
            blocked_ips.add(ip)
        else:
            print(f"Warning: Cannot block IP {ip}. Need root privileges to use iptables.")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip}: {e}")

def unblock_ip(ip):
    if ip not in blocked_ips:
        print(f"IP {ip} is not in the block list.")
        return False
        
    try:
        # Check if running as root (required for iptables)
        if os.geteuid() == 0:
            subprocess.run(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'], check=True)
            print(f"Unblocked IP: {ip}")
            blocked_ips.remove(ip)
            return True
        else:
            print(f"Warning: Cannot unblock IP {ip}. Need root privileges to use iptables.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip}: {e}")
        return False

def clear_block_list():
    if not blocked_ips:
        print("Block list is already empty.")
        return
        
    success = True
    for ip in list(blocked_ips):
        if not unblock_ip(ip):
            success = False
    
    if success:
        print("Successfully cleared all IPs from block list.")
    else:
        print("Some IPs could not be unblocked. Check permissions.")


def view_live_traffic():
    flag = True
    print("\nPress Ctrl+C to stop viewing live traffic...")
    try:
        global running
        was_running = running
        running = True
        
        sniff(prn=partial(packet_callback, flag = True), store=0)
        running = was_running
    except KeyboardInterrupt:
        print("\nStopped viewing live traffic.")
        running = was_running

def view_intrusion_logs():
    try:
        if not os.path.exists('ids.log'):
            print("No log file found.")
            return
            
        with open('ids.log', 'r') as log_file:
            logs = log_file.readlines()
            
        if not logs:
            print("Log file is empty.")
            return

        print("\n== Latest Intrusion Logs ==")
        for log in logs[-10:]:
            print(log.strip())
        
        print(f"\nShowing last {min(10, len(logs))} of {len(logs)} log entries.")
        print("To see all logs, check the ids.log file.")
    except Exception as e:
        print(f"Error reading log file: {e}")

def start_ids():
    global running
    if running:
        print("IDS is already running.")
        return
        
    running = True
    print("Starting IDS... Press Ctrl+C in the main menu to stop.")
    
    # sniff_thread = threading.Thread(target=lambda: sniff(prn=partial(packet_callback, flag=False), store=0))
    sniff_thread = threading.Thread(target=lambda: sniff(prn=partial(packet_callback, flag = False), store=0))
    sniff_thread.daemon = True
    sniff_thread.start()

def stop_ids():
    flag = False
    global running
    if not running:
        print("IDS is already stopped.")
        return
    running = False
    print("IDS stopped.")

def display_menu():
    menu_items = [
        "1. Start IDS" if not running else "1. Stop IDS",
        "2. View Live Traffic",
        "3. View Intrusion Logs",
        "4. Display Blocked IPs",
        "5. Unblock an IP",
        "6. Clear Block List",
        "7. Exit"
    ]
    
    print("\n" + "=" * 50)
    print("Network Intrusion Detection and Prevention System (NIDPS)")
    print("=" * 50)
    
    status = "Running" if running else "Stopped"
    print(f"Status: {status}")
    print(f"Blocked IPs: {len(blocked_ips)}")
    
    print("\nMenu Options:")
    for item in menu_items:
        print(item)
    
    print("=" * 50)

def handle_menu_choice():
    try:
        choice = input("Enter your choice (1-7): ")
        
        if choice == '1':
            if not running:
                start_ids()
            else:
                stop_ids()
        
        elif choice == '2':
            if running:
                view_live_traffic()
            else:
                print("Start IDS first using option 1")
        elif choice == '3':
            view_intrusion_logs()
        elif choice == '4':
            if not blocked_ips:
                print("No IPs are currently blocked.")
            else:
                print("\nBlocked IPs:")
                for ip in blocked_ips:
                    print(f"- {ip}")
        elif choice == '5':
            ip = input("Enter the IP address to unblock: ")
            if validate_ip(ip):
                unblock_ip(ip)
            else:
                print("Invalid IP address format.")
        elif choice == '6':
            clear_block_list()
        elif choice == '7':
            if running:
                stop_ids()
            print("Exiting NIDPS. Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice. Please enter a number between 1 and 8.")
    except Exception as e:
        print(f"Error: {e}")

def main():
    # Check if running as root for iptables functionality
    if os.geteuid() != 0:
        print("Warning: Not running as root. Some features (IP blocking) will be limited.")
    
    print("Network Intrusion Detection and Prevention System (NIDPS)")
    print("Press Ctrl+C to exit at any time.")
    
    try:
        while True:
            display_menu()
            handle_menu_choice()
    except KeyboardInterrupt:
        print("\nExiting NIDPS. Goodbye!")
        if running:
            stop_ids()
        sys.exit(0)

if __name__ == "__main__":
    main()