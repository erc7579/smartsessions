#!/bin/bash

# Check if a contract name is provided
if [ $# -eq 0 ]; then
    echo "Please provide a contract name as an argument."
    echo "Usage: $0 <ContractName>"
    exit 1
fi

CONTRACT_NAME=$1

mkdir -p ./artifacts/$CONTRACT_NAME
forge build $CONTRACT_NAME
cp ./out/$CONTRACT_NAME.sol/* ./artifacts/$CONTRACT_NAME/.
forge verify-contract --show-standard-json-input $(cast address-zero) $CONTRACT_NAME > ./artifacts/$CONTRACT_NAME/verify.json

