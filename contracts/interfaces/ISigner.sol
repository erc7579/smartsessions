// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import "../DataTypes.sol";

// Probably merge with Kernel's ISigner

interface ISigner is IERC7579Module {
    function checkSignature(
        SessionId signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (bytes4);
}
