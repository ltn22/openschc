#!/usr/bin/env python3
from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('trace_coap.pcap')

flowlabel = []

for packet in packets:
    packet.show()
    if packet[IPv6].fl not in flowlabel:
        flowlabel.append(packet[IPv6].fl)
    hexdump(packet)

    print ("="*40)

print ("Flow Label found:", flowlabel)