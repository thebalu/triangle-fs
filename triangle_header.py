from scapy.all import *
import sys, os

TYPE_TRIANGLE = 0x1212
TYPE_IPV4 = 0x0800

class Triangle(Packet):
    name = "Triangle"
    fields_desc = [
        ShortField("pid", 0),
        ShortField("dst_id", 0),
        ShortField("is_new", 0),
        ShortField("is_query", 0),
        ShortField("is_delete", 0),
        IntField("packet_id", 0)
    ]
    def mysummary(self):
        return self.sprintf("pid=%pid%, dst_id=%dst_id%, is_new=%is_new%, is_query=%is_query%, is_delete=%is_delete%, packet_id=%packet_id%")


bind_layers(Ether, Triangle, type=TYPE_TRIANGLE)
bind_layers(Triangle, IP, pid=TYPE_IPV4)