import sys, os 
# insert at 1, 0 is the script path (or '' in REPL)

sys.path.insert(1, '../../src/')

import gen_rulemanager as RM

import pprint
import binascii
import base64

import cbor2 as cbor

#from yangson import DataModel

if len(sys.argv) < 2:
    print("Usage: python data_model_simple.py <rule-file.json>")
    sys.exit(1)

rule_file = sys.argv[1]

rm    = RM.RuleManager()
rm.Add(file=rule_file, device="test:device1")
rm.Print()

rm.add_sid_file("ietf-schc-unified.sid")
rm.add_sid_file("ietf-schc-quentin@2025-03-21.sid")

ycbor = rm.to_coreconf()
print (binascii.hexlify(ycbor))
pprint.pprint(cbor.loads(ycbor))

#yr = rm.convert_to_json (cbor.loads(ycbor))
#pprint.pprint(yr)

# Store ycbor in a file with .cbor extension
cbor_filename = rule_file.replace(".json", ".sor")
with open(cbor_filename, "wb") as f:
    f.write(ycbor)

#yr = rm.convert_to_json (cbor.loads(ycbor))
#pprint.pprint(yr)

