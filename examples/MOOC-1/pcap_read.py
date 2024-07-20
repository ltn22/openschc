#!/usr/bin/env python3
from scapy.all import *

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('eap-edhoc_802-11_eap.cap')

for packet in packets:
    packet.show()

    hexdump(packet)

    print ("="*40)