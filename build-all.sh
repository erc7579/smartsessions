#!/bin/bash

# Array of contract names to build
CONTRACTS=(
    "./contracts/SmartSession.sol"
    "./contracts/SmartSessionCompatibilityFallback.sol"
    "./contracts/external/policies/SudoPolicy.sol"
    "./contracts/external/policies/SimpleGasPolicy.sol"
    "./contracts/external/policies/TimeFramePolicy.sol"
    "./contracts/external/policies/UniActionPolicy.sol"
    "./contracts/external/policies/UsageLimitPolicy.sol"
    "./contracts/external/policies/ValueLimitPolicy.sol"
    "./contracts/external/policies/ContractWhitelistPolicy.sol"
    "./contracts/external/policies/ERC20SpendingLimitPolicy.sol"
    "./contracts/external/policies/ArgPolicy/ArgPolicy.sol"
  )
# Loop through the contracts and run build-artifacts.sh for each
for CONTRACT in "${CONTRACTS[@]}"; do
    echo "Building artifacts for $CONTRACT..."
    ./build-artifacts.sh "$CONTRACT"
    
    # Check the exit status of the previous command
    if [ $? -eq 0 ]; then
        echo "Successfully built artifacts for $CONTRACT"
    else
        echo "Failed to build artifacts for $CONTRACT"
        # Optionally, you can choose to exit the script on first failure
        # exit 1
    fi
done

echo "Artifact build process completed."
