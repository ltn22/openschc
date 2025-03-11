#!/usr/bin/env python3
from scapy.all import *

import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from compr_parser import Parser, Unparser
from gen_parameters import *
from gen_rulemanager import RuleManager
from compr_core import Compressor, Decompressor

import pprint
import binascii

# rdpcap comes from scapy and loads in our pcap file
packets = rdpcap('trace_coap.pcap')

parser = Parser()
Unparser = Unparser()

RM = RuleManager()
RM.Add(file="coap.json")
RM.Print()

compress = Compressor()
decompress = Decompressor()

def show_diff(s1, s2):
    from termcolor import colored

    if len(s1) != len(s2):
        print("size is different")
        return
    
    differ = False
    for o, c in zip(s1, s2):
        #print(o, c)
        if o == c:
            print(colored(chr(o), "green"), end="")
        else:
            print(colored(chr(o), "red"), end="")  
            differ = True 
    print()         
    if differ:
        print (s2.decode()) 


# Let's iterate through every packet
for packet in packets:

    if packet[Ether].src == "fa:16:3e:1e:cc:2c":
        direction = T_DIR_DW
    elif packet[Ether].dst == "fa:16:3e:1e:cc:2c":
        direction = T_DIR_UP
    else: # skipping
        break

    print ("Packet direction ", direction)

    parsed = parser.parse (bytes(packet[IPv6]), 
                           direction, 
                           layers=["IPv6", "UDP", "CoAP"])
    
    if parsed[0] != None:
        rule = RM.FindRuleFromPacket(pkt=parsed[0], 
                                     direction=direction, 
                                     failed_field=True)

        if rule:
            SCHC_pkt = compress.compress(rule=rule,
                                         parsed_packet=parsed[0],
                                         data= parsed[1],
                                         direction=direction)
            
            print ("Original packet size (in byte)", len(bytes(packet)[14:]))
            print ("Compressed packet (in byte)", len(SCHC_pkt._content))
            
            field_description = decompress.decompress(rule=rule, 
                                                  schc=SCHC_pkt, 
                                                direction=direction)
            
            SCHC_pkt.display(format="bin")
            data = SCHC_pkt.get_remaining_content()

            pkt = Unparser.unparse(header_d=field_description, 
                                   data=data, 
                                   direction=direction)

            show_diff(binascii.hexlify(bytes(packet)[14:]), 
                      binascii.hexlify(bytes(pkt)))
                      
 

