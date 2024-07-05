// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

import "forge-std/console2.sol";

contract YesPolicy is IUserOpPolicy, IActionPolicy {
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        userOpState;

    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        actionState;

    function isInitialized(address smartAccount) external view returns (bool) { }

    function onInstall(bytes calldata data) external { }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) { }

    function initForAccount(address account, SessionId id, bytes calldata initData) external override {
        userOpState[id][msg.sender][account] = 1;
    }

    function isInitialized(address account, SessionId id) external override returns (bool) {
        return userOpState[id][msg.sender][account] != 0;
    }

    function checkUserOp(SessionId id, PackedUserOperation calldata userOp) external override returns (uint256) {
        userOpState[id][msg.sender][userOp.sender] += 1;
    }

    function checkAction(
        SessionId id,
        address sender,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        actionState[id][msg.sender][sender] += 1;
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }
}
