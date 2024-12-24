

#!/bin/bash



mkdir -p ./artifacts/SmartSession
forge build contracts/SmartSession.sol
cp ./out/SmartSession.sol/* ./artifacts/SmartSession/.
forge verify-contract --show-standard-json-input $(cast address-zero) ./contracts/SmartSession.sol:SmartSession > ./artifacts/SmartSession/verify.json



mkdir -p ./artifacts/SudoPolicy
forge build contracts/external/policies/SudoPolicy.sol
cp ./out/SudoPolicy.sol/* ./artifacts/SudoPolicy/.
forge verify-contract --show-standard-json-input $(cast address-zero) ./contracts/external/policies/SudoPolicy.sol:SudoPolicy > ./artifacts/SudoPolicy/verify.json

mkdir -p ./artifacts/ERC20SpendingLimitPolicy
forge build contracts/external/policies/ERC20SpendingLimitPolicy.sol
cp ./out/ERC20SpendingLimitPolicy.sol/* ./artifacts/ERC20SpendingLimitPolicy/.
forge verify-contract --show-standard-json-input $(cast address-zero) ./contracts/external/policies/ERC20SpendingLimitPolicy.sol:ERC20SpendingLimitPolicy > ./artifacts/ERC20SpendingLimitPolicy/verify.json


mkdir -p ./artifacts/UniActionPolicy
forge build contracts/external/policies/UniActionPolicy.sol
cp ./out/UniActionPolicy.sol/* ./artifacts/UniActionPolicy/.
forge verify-contract --show-standard-json-input $(cast address-zero) ./contracts/external/policies/UniActionPolicy.sol:UniActionPolicy > ./artifacts/UniActionPolicy/verify.json




