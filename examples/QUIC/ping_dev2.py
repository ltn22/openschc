import sys
# insert at 1, 0 is the script path (or '' in REPL)
sys.path.insert(1, '../../src/')

from scapy.all import *

import gen_rulemanager as RM
from protocol import SCHCProtocol
from gen_parameters import T_POSITION_DEVICE

import netifaces as ni

import socket
import select
import time

addr = ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']

PORT = 8888
deviceID = "udp:"+addr+":"+str(PORT)

print("device ID is", deviceID)

tunnel = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
tunnel.bind (("0.0.0.0", PORT)) # same port as in the DeviceID
# Create a Rule Manager and upload the rules.

rm = RM.RuleManager()
rm.Add(file="icmp-bi.json")
rm.Print()

core_id = None

# Start SCHC Machine
POSITION = T_POSITION_DEVICE

schc_machine = SCHCProtocol(role=POSITION, tunnel=tunnel)           
schc_machine.set_rulemanager(rm)
scheduler = schc_machine.system.get_scheduler()
tunnel = schc_machine.get_tunnel()

t = AsyncSniffer(iface="eth0", store=False) 
t.start()
print ("sniff started")

toto
