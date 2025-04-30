import subprocess
import sys
from termcolor import cprint

COMMANDS = [
    'iptables -F',
    'iptables -t nat -F',
    'iptables --policy FORWARD ACCEPT',
    'sysctl -w net.ipv4.ip_forward=1',
    'iptables -t nat -A PREROUTING -i eth0 -p udp --dport 53 -j REDIRECT --to-port 53',
    'iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080',
    'iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080'
]

def run():
    print('Configuring attacker machine as a router...')
    for c in COMMANDS:
        cprint(f'Executing: {c}', 'light_grey', attrs=['dark'])
        command = subprocess.run(c.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        if command.returncode != 0:
            print(f'Error in executing: {c}')
            sys.exit(1)

