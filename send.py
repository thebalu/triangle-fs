#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct
import argparse

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, hexdump
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from triangle_header import Triangle

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():
    parser = argparse.ArgumentParser()
    # parser.add_argument('ip_addr', type=str, help="The destination IP address to use")
    parser.add_argument('message', type=str, help="The message to include in packet")
    parser.add_argument('--packet_id', type=int, default=None, help='The packet_id to use ')
    parser.add_argument('--query', dest='query', action='store_true', help='Query the packet with given id')
    parser.add_argument('--delete', dest='delete', action='store_true', help='Delte the packet with given id')

    args = parser.parse_args()

    # addr = socket.gethostbyname(args.ip_addr)
    packet_id = args.packet_id
    iface = get_if()

    dst_id = 1
    if args.query == 1 or args.delete == 1:
        dst_id = 2

    if (packet_id is not None):
        print "sending on interface {} to packet_Id {}".format(iface, str(packet_id))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / Triangle(packet_id=packet_id, status=0, dst_id=dst_id, is_new=1, is_query=args.query, is_delete=args.delete) / args.message
    else:
        raise 'No packet id given'
        #pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        #t = pkt / IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / args.message

    pkt.show2()
#    hexdump(pkt)
#    print "len(pkt) = ", len(pkt)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
