import subprocess
import time
import os
from scapy.all import IP, TCP, send

def generate_fake_ips(count):
    fake_ips = []
    for i in range(count):
        fake_ips.append(f"10.0.0.{175 + i}")
    return fake_ips


def simulate_port_scan(target_ip, source_ip):
    print(f"[TEST] Simulating Port Scan from {source_ip} to {target_ip}")
    ports = [22, 53, 443, 3306, 5000, 8000]
    for port in ports:
        pkt = IP(src=source_ip, dst=target_ip)/TCP(dport=port, flags='S')
        send(pkt, verbose=0)
        time.sleep(0.5)

def simulate_sequential_port_scan(target_ip, source_ip):
    print(f"[TEST] Simulating Sequential Port Scan on {target_ip}")

    for port in [80, 81, 82, 83, 84, 85]:
        pkt = IP(src=source_ip, dst=target_ip)/TCP(dport=port, flags='S')
        send(pkt, verbose=0)
        time.sleep(0.5)

def simulate_os_fingerprinting(target_ip, source_ip):
    print(f"[TEST] Simulating OS Fingerprinting on {target_ip}")
    flags_list = ['S', 'A', 'F', 'P', 'R']
    for flag in flags_list:
        pkt = IP(src=source_ip, dst=target_ip)/TCP(dport=80, flags=flag)
        send(pkt, verbose=0)
        time.sleep(0.5)

def test_iptables_block(ip):
    print(f"[TEST] Testing iptables block on {ip}")
    subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    result = subprocess.call(["ping", "-c", "1", ip], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result != 0:
        print("[PASS] IP successfully blocked.")
    else:
        print("[FAIL] IP block failed.")


def check_log_file():
    print("[TEST] Checking for intrusion log entries...")
    if not os.path.exists("ids.log"):
        print("[FAIL] Log file not found.")
        return

    with open("ids.log", "r") as log:
        lines = log.readlines()
        if lines:
            print("[PASS] Log file contains entries.")
            print("Last entry:")
            print(lines)
        else:
            print("[FAIL] Log file is empty.")

def run_all_tests(target_ip):
    fake_ips = generate_fake_ips(count=3)
    print("\n====== Starting NIDPS Functionality Tests ======\n")
    simulate_port_scan(target_ip, fake_ips[0])
    time.sleep(2)
    simulate_sequential_port_scan(target_ip, fake_ips[1])
    time.sleep(2)
    simulate_os_fingerprinting(target_ip, fake_ips[2])
    time.sleep(2)
    check_log_file()
    test_iptables_block(target_ip)
    print("\n====== All Tests Completed ======\n")

if __name__ == "__main__":
    target_ip = "192.168.1.5"
    run_all_tests(target_ip)
