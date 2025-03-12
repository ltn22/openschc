import json
import csv
import pprint
import sys

if len(sys.argv) != 4:
    sys.exit(f"{sys.argv[0]} requires 'csv file' 'pyang sid file' 'result file'")


csv_name  = sys.argv[1]
sid_orig  = sys.argv[2]
sid_final = sys.argv[3]

with open(sid_orig) as sid_file:
    sid_module = json.load(sid_file)

allocation_table = []

with open(csv_name, newline='') as cvs_file:
    csv_data = csv.reader(cvs_file)

    for row in csv_data:
        if row[1] in ["identity", "module", "data", "feature"]:
            assert (len(row)==3) 
            allocation_table.append([row[0], row[1], row[2]])

def take_from_allocation(sid, namespace, identifier):
    for row in allocation_table:
        if row[1] in ["identity", "module", "data", "feature"]:
            assert (len(row)==3)
            if namespace == row[1] and identifier == row[2]:
                return (row)
        

    return None

new_items = []
unknown_items =[]

for i in range(len(sid_module["items"])):
    item = sid_module["items"].pop(0)
    result = take_from_allocation(item["sid"], item["namespace"], item["identifier"])
    if result != None:
        print (f"{item['identifier']:30}:{item['sid']:6} ==> {result[0]:6}")
        item["sid"] == result[0]
        new_items.append(item)
    else:
        unknown_items.append(item)

if len(unknown_items) == 0:
    sid_module["items"] = new_items

    with open(sid_final, "w") as output_file:
        json.dump(sid_module, output_file, indent=4)
else:
    print("Transposition failed, unknown items:")
    pprint.pprint (unknown_items)