import socket
from termcolor import colored
from IPy import IP

def check_target(ip):
    try:
        IP(ip)
        return(ip)
    except ValueError:
        return socket.gethostbyname(ip)

def scan_port(ipaddress, port, time):
    try:
        sock = socket.socket()
        sock.settimeout(time)
        sock.connect((ipaddress, port))
        try:
            port_banners = get_port_banner(sock)
            print(colored("\n[+] Port " + str(port) + ' is open: ' + str(port_banners.decode().strip('\n')) + ' [+]', 'green', attrs=['bold']))
        except:
            print(colored("\n[+] Port " + str(port) + ' is open [+]', 'green', attrs=['bold']))
    except:
        pass

def scan(target, port):
    converted_ip = check_target(target)
    print(colored('\n' + '|\/| Scanning Target ---> ' + str(target), 'green', attrs=['bold']))
    for ports in range(1, port):
        scan_port(target, ports, scan_type)

def get_port_banner(s):
    return s.recv(1024)



targets = input(colored("Enter your target/targets(split with ',' for multiple targets) IP or hostname(eg - google.com): ", 'green', attrs=['bold']))
port = int(input(colored("Enter your target port range(100 means first 100 ports): ", 'green', attrs=['bold'])))
scan_type = input(colored("Enter the priority of scan(High, Medium, Low: Higher the priority more precise and slower the scan): ", 'green', attrs=['bold']))
if scan_type == 'High' or scan_type == 'high':
    scan_type = 3
elif scan_type == 'Low' or scan_type == 'low':
    scan_type = 0.5
elif scan_type == 'Medium' or scan_type == 'medium':
    scan_type = 1
else:
    print(colored("[-] Please enter the priority correctly [-]"))
print(colored("\n[+] Portscanner Started [+]", 'green', attrs=['bold', 'blink']))
if ',' in targets:
    for ip_addy in targets.split(','):
        scan(ip_addy.strip(' '), port)
else:
    scan(targets, port)

print(colored('\n[+] Scanning finished successfully [+]', 'green', attrs=['bold', 'blink']))