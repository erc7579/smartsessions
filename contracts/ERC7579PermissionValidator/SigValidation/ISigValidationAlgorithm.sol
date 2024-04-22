// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

interface ISigValidationAlgorithm {
    function validateSignature(
        bytes32 dataHash,
        bytes memory signature,
        bytes calldata signer
    )
        external
        view
        returns (bool);
}
