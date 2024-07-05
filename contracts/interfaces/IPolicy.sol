// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { IModule as IERC7579Module, VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";
import "../DataTypes.sol";
import "forge-std/interfaces/IERC165.sol";

interface ISubPermission is IERC165, IERC7579Module {
    function initForAccount(address account, SessionId id, bytes calldata initData) external;
    function deinitForAccount(address account, SessionId id) external;
    function isInitialized(address account, SessionId id) external returns (bool);
}

interface IUserOpPolicy is ISubPermission {
    // MUST implement mapping(id => msg.sender => userOp.sender => state);
    function checkUserOpPolicy(SessionId id, PackedUserOperation calldata userOp) external returns (uint256);
}

interface IActionPolicy is ISubPermission {
    function checkAction(
        SessionId id,
        address sender,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256);
}

interface I1271Policy is ISubPermission {
    // request sender is probably protocol, so can introduce policies based on it.
    function check1271SignedAction(
        SessionId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);
}
