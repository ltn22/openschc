#!/usr/bin/env python3
from scapy.all import *
import binascii

from torch import binary_cross_entropy_with_logits

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('trace_coap.pcap')

type_name = ["CON", "NON", "ACK", "RST" ]

for packet in packets:
    #packet.show()
    #hexdump(packet)
    #print ("="*40)

    coap = bytes(packet[Raw])
    print ("CoAP Header", binascii.hexlify(coap[:4]), end="")
    version = coap[0]>> 6
    type_field = (coap[0] & 0b0011_0000) >> 4
    tkl = coap[0] & 0b0000_1111

    print (": version", version, 
           "type", type_field, type_name[type_field], 
           "token length", tkl, end="")
    
    print (" Code {:3} ({:1}.{:02})".format(
        coap[1], 
        coap[1]>>5, 
        coap[1] & 0b000_11111), end="")

    print (" MID:", (coap[2]<<8)|coap[3], end="")

    if tkl > 0:
        print(" Token:", binascii.hexlify(coap[4:4+tkl]))
    else:
        print ("No token")

        