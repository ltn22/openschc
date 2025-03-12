from scapy.all import *

packets = rdpcap('trace_coap.pcap')

for p in packets:
    p.show()

    del p[UDP].chksum

    p.show2()

    print("-"*20)

wrpcap("fixed.pcap",packets)

    