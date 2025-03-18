import sys, os

# insert at 1, 0 is the script path (or '' in REPL)

sys.path.insert(1, '../../src/')

import gen_rulemanager as RM
from compr_parser import Parser
from gen_parameters import T_DIR_DW 
from compr_core import Compressor


import pprint
import binascii
import base64

import cbor2 as cbor

from yangson import DataModel

parser = Parser() 

coap_message_txt = "40 01 00 01 BD 01 61 63 63 65 6C 65 72 6F 6D 65" \
                   "74 65 72 73 07 6D 61 78 69 6D 75 6D 4A 64 61 74" \
                   "65 3D 74 6F 64 61 79 0A 75 6E 69 74 3D 6D 2F 73" \
                   "5E 32 21 3C D1 E4 02 E3 05 F8 54 4C 56"

coap_message = binascii.unhexlify(coap_message_txt.replace(' ', ''))

# Now with Universal Option

parsed = parser.parse(coap_message, T_DIR_DW, start="CoAP", quentin=True)
pprint.pprint (parsed[0])

0/0

rm2    = RM.RuleManager(universal_option=True)
rm2.Add(file="coap+UO.json", device="test:device1")
rm2.Print()



if parsed[0] != None:
        rule = rm2.FindRuleFromPacket(pkt=parsed[0], 
                                     direction=T_DIR_DW, 
                                     failed_field=True)    
        print (rule)

        if rule:
            compress = Compressor()

            SCHC_pkt2 = compress.compress(rule=rule,
                                         parsed_packet=parsed[0],
                                         data= parsed[1],
                                         direction=T_DIR_DW,
                                         verbose=True)
            
            print("SCHC packet in hex")
            SCHC_pkt2.display()

#rm2.add_sid_file("ietf-schc@2023-01-28.sid")
#rm2.add_sid_file("ietf-schc-opt@2024-12-19.sid")

rm2.add_sid_file("ietf-schc-allo.sid")

ycbor2 = rm2.to_coreconf()
print(binascii.hexlify(ycbor2))