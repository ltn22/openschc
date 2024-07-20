#!/usr/bin/env python3
from scapy.all import *

import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from compr_parser import Parser
from gen_parameters import *

import pprint

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('eap-edhoc_802-11_eap.cap')

parser = Parser()

# Let's iterate through every packet
for packet in packets:
    hexdump(packet[EAPOL])
    packet[EAPOL].show()

    if packet[Dot11].addr1 == "e8:94:f6:20:41:fd":
        direction = T_DIR_DW
    elif packet[Dot11].addr2 == "e8:94:f6:20:41:fd":
        direction = T_DIR_UP
    else: # skipping
        print ("Direction unknown")
        break

    print ("Packet direction ", direction)

    parsed = parser.parse (bytes(packet[EAPOL]), 
                           direction, 
                           layers=["EAPOL", "EAP"],
                           start="EAPOL" )
    pprint.pprint (parsed)

