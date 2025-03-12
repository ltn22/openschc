#!/usr/bin/env python3
from scapy.all import *

import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from compr_parser import Parser
from gen_parameters import *

import pprint

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('trace2.pcap')

parser = Parser()

# Let's iterate through every packet
for packet in packets:
    hexdump(packet[IPv6])
    packet[IPv6].show()

    direction = T_DIR_DW


    print ("Packet direction ", direction)

    parsed = parser.parse (bytes(packet[IPv6]), 
                           direction, 
                           layers=["IPv6", "UDP", "CoAP"])
    pprint.pprint (parsed)

