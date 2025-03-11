import pytest
from scapy.all import rdpcap, hexdump

#============================ defines =========================================

JSON_RULE = [{
    "RuleIDValue": 5,
    "RuleIDLength": 3,
    "Compression": [
      {"FID": "IPV6.VER", "TV": 6, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.TC",  "TV": 0, "MO": "ignore", "CDA": "value-sent"},
      {"FID": "IPV6.FL",  "TV": 0, "MO": "ignore","CDA": "value-sent"},
      {"FID": "IPV6.LEN",          "MO": "ignore","CDA": "compute-length"},
      {"FID": "IPV6.NXT", "TV": 17, "MO": "ignore", "CDA": "value-sent"},
      {"FID": "IPV6.HOP_LMT", "TV" : 255,"MO": "ignore","CDA": "not-sent"},
      {"FID": "IPV6.DEV_PREFIX","TV": ["2001:db8::/64",
                                       "fe80::/64",
                                       "2001:41d0:0404:0200::/64" ],
                                         "MO": "match-mapping","CDA": "mapping-sent"},
      {"FID": "IPV6.DEV_IID", "TV": "::3a86","MO": "equal","CDA": "DEVIID"},
      {"FID": "IPV6.APP_PREFIX","TV": [ "2001:41d0:0302:2200::/64",
                                        "fe80::/64",
                                        "2404:6800:4004:818::/64" ],
                                         "MO": "match-mapping","CDA": "mapping-sent"},
      {"FID": "IPV6.APP_IID", "TV": 5043,"MO": "equal","CDA": "not-sent"},
      {"FID": "UDP.DEV_PORT",  "TV": 44981,"MO": "equal",  "CDA": "not-sent"},
      {"FID": "UDP.APP_PORT",  "TV": 5680,"MO": "MSB", "MO.VAL": 12, "CDA" : "LSB"},
      {"FID": "UDP.LEN",       "TV": 0,   "MO": "ignore","CDA": "compute-length"},
      {"FID": "UDP.CKSUM",     "TV": 0,  "MO": "ignore","CDA": "compute-checksum"},
      {"FID": "COAP.VER", "TV": 1,    "MO": "equal","CDA": "not-sent"},
      {"FID": "COAP.TYPE",                "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.TKL",                 "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.CODE",                "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.MID",                 "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.TOKEN",                 "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.Uri-Path", "FL": "var", "FP": 1, "DI": "UP", "TV": "time","MO": "equal","CDA": "not-sent"},
      {"FID": "COAP.Uri-Path", "FL": "var", "FP": 2, "DI": "UP", "TV": ["bar", "toto"] ,"MO": "match-mapping","CDA": "mapping-sent"},
      {"FID": "COAP.Uri-Path", "FL": "var", "FP": 3, "DI": "UP",             "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.Uri-Path", "FL": "var", "FP": 4, "DI": "UP",             "MO": "ignore","CDA": "value-sent"},
      {"FID": "COAP.Uri-Query", "FL": "var", "FP": 1, "DI": "UP", "TV":"k=", "MO": "MSB", "MO.VAL": 16, "CDA": "LSB"},
      {"FID": "COAP.Content-Format",                  "DI": "DW", "TV": 30, "MO": "equal", "CDA": "not-sent"}
    ]
},{
    "RuleID": 6,
    "RuleIDLength": 3,
    "Compression": [
      {"FID": "IPV6.VER", "TV": 6, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.TC",  "TV": 0, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.FL",  "TV": 0, "MO": "ignore","CDA": "not-sent"},
      {"FID": "IPV6.LEN",          "MO": "ignore","CDA": "compute-length"},
      {"FID": "IPV6.NXT", "TV": 58, "MO": "equal", "CDA": "not-sent"},
      {"FID": "IPV6.HOP_LMT", "TV" : 255,"MO": "ignore","CDA": "not-sent"},
      {"FID": "IPV6.DEV_PREFIX","TV": ["2001:db8::/64",
                                       "fe80::/64",
                                       "2001:41d0:0404:0200::/64" ],
                                         "MO": "match-mapping","CDA": "mapping-sent"},
      {"FID": "IPV6.DEV_IID", "TV": "::3a86","MO": "equal","CDA": "DEVIID"},
      {"FID": "IPV6.APP_PREFIX","TV": [ "2001:41d0:0302:2200::/64",
                                        "fe80::/64",
                                        "2404:6800:4004:818::/64" ],
                                         "MO": "match-mapping","CDA": "mapping-sent"},
      {"FID": "IPV6.APP_IID", "TV": 5043,"MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.TYPE",  "TV": 128,"MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.CODE",  "TV": 0,  "MO": "equal","CDA": "not-sent"},
      {"FID": "ICMPV6.CKSUM", "TV": 0, "MO": "ignore","CDA": "compute-checksum"},
      {"FID": "ICMPV6.IDENT", "TV": 0,"MO": "ignore","CDA": "value-sent"},
      {"FID": "ICMPV6.SEQNO", "TV": 0,"MO": "ignore","CDA": "value-sent"}
    ]
}
]

ETHERNET_HEADER_LENGTH = 14
EXPECTED_RESULTS_IPv6_UDP = ({('IPV6.VER', 1): [b'\x06', 4], ('IPV6.TC', 1): [b'\x00', 8], 
    ('IPV6.FL', 1): [b'\x03*&', 20], ('IPV6.LEN', 1): [b' ', 16, 'fixed'], 
    ('IPV6.NXT', 1): [b'\x11', 8, 'fixed'], ('IPV6.HOP_LMT', 1): [b'0', 8, 'fixed'], 
    ('IPV6.DEV_PREFIX', 1): [b' \x01A\xd0\x04\x04\x02\x00', 64], 
    ('IPV6.DEV_IID', 1): [b'\x00\x00\x00\x00\x00\x00:\x86', 64], 
    ('IPV6.APP_PREFIX', 1): [b' \x01A\xd0\x03\x02"\x00', 64], 
    ('IPV6.APP_IID', 1): [b'\x00\x00\x00\x00\x00\x00\x13\xb3', 64], 
    ('UDP.DEV_PORT', 1): [b'\xaf\xb5', 16], ('UDP.APP_PORT', 1): [b'\x163', 16], 
    ('UDP.LEN', 1): [b' ', 16], ('UDP.CKSUM', 1): [b'\xed\\', 16], 
    ('COAP.VER', 1): [b'\x01', 2], ('COAP.TYPE', 1): [b'\x00', 2], ('COAP.TKL', 1): [b'\x02', 4], 
    ('COAP.CODE', 1): [b'\x01', 8], ('COAP.MID', 1): [b'\x81B', 16], ('COAP.TOKEN', 1): [b'\xdd\xad', 16], 
    ('COAP.Uri-Host', 1): [b'user.ackl.io', 96, 'variable'], ('COAP.Uri-Path', 1): [b'time', 32, 'variable']},
    b'', None)

EXPECTED_RESULTS_ICMP = ({('IPV6.VER', 1): [b'\x06', 4], ('IPV6.TC', 1): [b'\x00', 8], 
    ('IPV6.FL', 1): [b'\x0b$-', 20], ('IPV6.LEN', 1): [b'P', 16, 'fixed'], 
    ('IPV6.NXT', 1): [b':', 8, 'fixed'], ('IPV6.HOP_LMT', 1): [b'@', 8, 'fixed'], 
    ('IPV6.DEV_PREFIX', 1): [b' \x01A\xd0\x03\x02"\x00', 64], 
    ('IPV6.DEV_IID', 1): [b'\x00\x00\x00\x00\x00\x00\x13\xb3', 64], 
    ('IPV6.APP_PREFIX', 1): [b' \x01A\xd0\x04\x04\x02\x00', 64], 
    ('IPV6.APP_IID', 1): [b'\x00\x00\x00\x00\x00\x00:\x86', 64], 
    ('ICMPV6.TYPE', 1): [b'\x01', 8], ('ICMPV6.CODE', 1): [b'\x04', 8], 
    ('ICMPV6.CKSUM', 1): [b'&G', 16], ('ICMPV6.UNUSED', 1): [b'\x00', 32], 
    ('ICMPV6.PAYLOAD', 1): [b'`\x03*&\x00 \x110 \x01A\xd0\x04\x04\x02\x00\x00\x00\x00\x00\x00\x00:\x86 \x01A\xd0\x03\x02"\x00\x00\x00\x00\x00\x00\x00\x13\xb3\xaf\xb5\x163\x00 \xed\\B\x01\x81B\xdd\xad<user.ackl.io\x84time', 576]}, 
    b'', None)
#============================ helpers =========================================

#============================ tests ===========================================

def test_import():
    import compr_parser
    import gen_rulemanager as RM

def test_rm():
    import compr_parser
    import gen_rulemanager as RM
    
    rm = RM.RuleManager()

    rm.Add(dev_info=JSON_RULE)

    parser = compr_parser.Parser(None)
    
    packets = []
    pcapngScanner = rdpcap("tests/coap_icmp.pcap")
    block = pcapngScanner[0]
    packet = bytes(block)[14:]  # skip Ethernet header
    parsed_IP_UDP_COAP = parser.parse(
        pkt       = packet,
        direction = 'UP',
        layers    = ["IPv6", "ICMP", "UDP", "CoAP"]
    )
    print (parsed_IP_UDP_COAP)
    found_rule = rm.FindRuleFromPacket (pkt=parsed_IP_UDP_COAP[0], direction='UP', failed_field=True)
    print (found_rule)


    
    assert (parsed_IP_UDP_COAP[1] == EXPECTED_RESULTS_IPv6_UDP[1]) # check data part

    block = pcapngScanner[1]
    packet = bytes(block)[14:]  # skip Ethernet header
    parsed_ICMP = parser.parse(
        pkt       = packet,
        direction = 'UP',
        layers    = ["IPv6", "ICMP", "UDP", "CoAP"]
    )

    assert (parsed_ICMP[2] == None) # no error during parsing

    for fd in parsed_ICMP[0]: # check Field Description
        expected_fields = EXPECTED_RESULTS_ICMP[0][fd]

        assert (parsed_ICMP[0][fd] == expected_fields)
    assert (parsed_ICMP[1] == EXPECTED_RESULTS_ICMP[1]) # check data part

    unparser = compr_parser.Unparser()

    udp_ip_coap = unparser.unparse(parsed_IP_UDP_COAP[0], parsed_IP_UDP_COAP[1], 'UP', None )

    print(bytes(udp_ip_coap))
    print(bytes(pcapngScanner[0])[14:] )

    assert(bytes(udp_ip_coap) == bytes(pcapngScanner[0])[14:] )

test_rm()
