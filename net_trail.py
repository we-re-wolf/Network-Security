import scapy.all as scapy
from termcolor import colored
import socket

def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_MAC = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast_MAC = broadcast_MAC/arp_request
    ans_list = scapy.srp(arp_request_broadcast_MAC, timeout=5, verbose=False)[0]
    print(colored("\nIP\t\t\tMAC ADDRESS\n------------------------------------------------", 'red', attrs=['bold']))
    for packets in ans_list:
        print(colored(packets[1].psrc + "\t\t" + packets[1].hwsrc, 'green', attrs=['bold']))

scan_ip = input(colored("Enter IP or IP range: ", 'cyan', attrs=['bold']))
scan(scan_ip)
