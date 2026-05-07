#!/bin/bash

# Script de debug pour lancer data_model_simple.py avec pdb
# Utilisation: ./debug_data_model_simple.sh [fichier_json]

if [ $# -eq 0 ]; then
    RULE_FILE="atmos41.json"
else
    RULE_FILE="$1"
fi

echo "Lancement du debug pour $RULE_FILE avec pdb..."
cd /Users/laurent/work/openschc/examples/datamodel
python3.9 -m pdb data_model_simple.py "$RULE_FILE"