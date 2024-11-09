#!/bin/bash

# Check if correct number of arguments are provided
if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <slot> <algorithm> <data_hex>"
    echo "Supported algorithms: RSA2048, ECCP256"
    echo "Data should ideally be in hex format"
    echo "Example: $0 9a RSA2048 "af821d1de86910351848afdc44a91d221c954c1eb20063ff07850afbdea92311""
    exit 1
fi

SLOT=$1
ALGO=$2
DATA=$3

echo $DATA > data.txt

# Sign the file using YubiKey, the specified slot, and the specified algorithm
yubico-piv-tool -a verify-pin --sign -s "$SLOT" -A "$ALGO" -i <(cat $DATA | xxd -r -p) -o data.sig

if [ $? -eq 0 ]; then
    echo "File successfully signed. Signature saved to data.sig"
else
    echo "Signing failed."
    exit 1
fi
