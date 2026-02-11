import sys, os 
# insert at 1, 0 is the script path (or '' in REPL)

sys.path.insert(1, '../../src/')

import gen_rulemanager as RM

import pprint
import binascii
import base64
import json

import cbor2 as cbor

from yangson import DataModel

with open("dev1-v.json", "r") as f:
    yr = json.load(f)

dm = DataModel.from_file("description.json")

print (dm.ascii_tree())

inst = dm.from_raw(yr)
print ("validation error ?", inst.validate())
#print(dm.ascii_tree(no_types=True, val_count=True), end='')

