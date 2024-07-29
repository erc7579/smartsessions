// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { ISubPermission } from "./IPolicy.sol";

interface ISigner is ISubPermission {
    function checkSignature(
        SessionId signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (bytes4);

    function checkUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256);

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        returns (bool validSig);
}
