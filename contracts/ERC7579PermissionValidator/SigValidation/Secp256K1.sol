// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { ISigValidationAlgorithm } from "./ISigValidationAlgorithm.sol";

import "forge-std/Console2.sol";

contract Secp256K1SigValidationAlgorithm is ISigValidationAlgorithm {
    using MessageHashUtils for bytes32;
    using ECDSA for bytes32;

    function validateSignature(
        bytes32 dataHash,
        bytes memory signature,
        bytes calldata signer
    )
        public
        pure
        returns (bool)
    {
        if(signature.length != 65) {
            revert("Invalid signature length");
        }

        //address recovered = (dataHash.toEthSignedMessageHash()).recover(signature);
        address recovered = dataHash.recover(signature);
        
        if (address(bytes20(signer[0:20])) != recovered) {
            revert("k1 sig validator: Invalid signature");
        }
        // omit for now
        /*
        recovered = dataHash.recover(signature);
        if (address(bytes20(signer[0:20])) == recovered) {
            return true;
        }
        return false;
        */
    }
}
