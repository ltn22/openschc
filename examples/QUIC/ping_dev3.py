import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from scapy.all import *

import socket

import gen_rulemanager as RM
from protocol import SCHCProtocol
from gen_parameters import T_POSITION_CORE

# Create a Rule Manager and upload the rules.

rm = RM.RuleManager()
rm.Add(file="icmp-bi.json")
rm.Print()

def processPkt(pkt):

    scheduler.run(session=schc_machine)

    if pkt.getlayer(Ether) != None: 
        e_type = pkt.getlayer(Ether).type
        if e_type == 0x86dd:
            schc_machine.schc_send(bytes(pkt)[14:])
        elif e_type == 0x0800:
            pkt.show()
            if pkt[IP].proto == 17 and pkt[UDP].sport == 0x5C4C:
                # got a packet in the socket
                SCHC_pkt, device = tunnel.recvfrom(1000)
                print (":")

                other_end = 'udp:'+device[0]+':'+str(8888)

                origin, full_packet = schc_machine.schc_recv(
                                   schc_packet=SCHC_pkt, 
                                   device_id=other_end, 
                                   iface='lo',
                                   verbose=True)

# Start SCHC Machine
POSITION = T_POSITION_CORE

tunnel = socket.socket (socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind((('0.0.0.0', 8888)))

schc_machine = SCHCProtocol(role=POSITION)           
schc_machine.set_rulemanager(rm)
scheduler = schc_machine.system.get_scheduler()

sniff(prn=processPkt, iface=["eth0", "lo"]) 




 
