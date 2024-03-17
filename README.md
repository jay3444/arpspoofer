This Python script is used to intercept network traffic between devices in a local area network. It is designed for educational purposes only.

Features
Sends spoofed ARP packets to target IP addresses.
Restores ARP tables to their original state after the attack.

Usage
Install scapy using pip:
pip install scapy
Enable IP forwarding:
sudo echo 1 > /proc/sys/net/ipv4/ipv4_forward

Run the script with the following command:
python3 arp_spoof.py [target_ip] [default_gatewayip]
Replace [target_ip] with the IP address of the target machine you want to spoof ARP packets for, and [gateway_ip] with the IP address of the gateway in the network.

Press Ctrl+C to stop the ARP spoofing attack and restore ARP tables.








