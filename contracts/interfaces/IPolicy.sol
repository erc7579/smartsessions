// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

import { PackedUserOperation, _packValidationData } from "modulekit/external/ERC4337.sol";
import { IModule as IERC7579Module, VALIDATION_SUCCESS, VALIDATION_FAILED } from "erc7579/interfaces/IERC7579Module.sol";
import "../DataTypes.sol";
import "forge-std/interfaces/IERC165.sol";

/**
 * ISubPermission are external contracts that enforce policies / permission on 4337/7579 executions
 * Since it's not the account calling into this contract, and check functions are called during the ERC4337 validation
 * phase, ISubPermission implementations MUST follow ERC4337 storage and opcode restructions
 * A recommend storage layout to store policy related data:
 *      mapping(id   =>   msg.sender   =>   userOp.sender(account) => state)
 *                        ^ smartSession    ^ smart account (associated storage)
 */
interface ISubPermission is IERC165, IERC7579Module {
    function isInitialized(address account, ConfigId configId) external view returns (bool);
    function isInitialized(address account, address mulitplexer, ConfigId configId) external view returns (bool);

    /**
     * This function may be called by the multiplexer (SmartSessions) without deinitializing first.
     * Policies MUST overwrite the current state when this happens
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external;
}

interface IUserOpPolicy is ISubPermission {
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external returns (uint256);
}

interface IActionPolicy is ISubPermission {
    function checkAction(
        ConfigId id,
        address account,
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
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);
}
