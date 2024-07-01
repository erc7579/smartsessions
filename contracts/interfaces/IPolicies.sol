// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { IModule as IERC7579Module, VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";

interface IUserOpPolicy is IERC7579Module {
    function checkUserOp(bytes32 id, PackedUserOperation calldata userOp) external returns (uint256);
}

interface IActionPolicy is IERC7579Module {
    function checkAction(
        bytes32 id,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata userOp
    )
        external
        returns (uint256);
}

interface I1271Policy is IERC7579Module {
    // request sender is probably protocol, so can introduce policies based on it.
    function check1271SignedAction(
        bytes32 id,
        address smartAccount,
        address requestSender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);
}
