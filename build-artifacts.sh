#!/bin/bash

# Check if a contract name is provided
if [ $# -eq 0 ]; then
    echo "Please provide a contract name as an argument."
    echo "Usage: $0 <ContractPath>"
    exit 1
fi

CONTRACT_PATH=$1
CONTRACT_NAME=$(basename "$CONTRACT_PATH" .sol)

mkdir -p ./artifacts/$CONTRACT_NAME
FOUNDRY_PROFILE=release forge build $CONTRACT_PATH
cp ./out/$CONTRACT_NAME.sol/* ./artifacts/$CONTRACT_NAME/.
forge verify-contract --show-standard-json-input $(cast address-zero) $CONTRACT_PATH:$CONTRACT_NAME > ./artifacts/$CONTRACT_NAME/verify.json
