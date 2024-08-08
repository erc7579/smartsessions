// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import "../DataTypes.sol";
import { ISubPermission } from "./IPolicy.sol";

interface ISigner is ISubPermission {
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        returns (bool validSig);
}
