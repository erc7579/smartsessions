// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import "contracts/lib/SubLib.sol";
import "forge-std/console2.sol";

contract YesPolicy is IUserOpPolicy, IActionPolicy {
    using SubLib for bytes;

    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        userOpState;

    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        actionState;

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        userOpState[id][msg.sender][opSender] = 1;
    }

    function onUninstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        userOpState[id][msg.sender][opSender] = 0;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function checkUserOpPolicy(SessionId id, PackedUserOperation calldata userOp) external override returns (uint256) {
        userOpState[id][msg.sender][userOp.sender] += 1;
        return 0;
    }

    function checkAction(
        SessionId id,
        address target,
        uint256 value,
        bytes calldata data,
        PackedUserOperation calldata op
    )
        external
        override
        returns (uint256)
    {
        actionState[id][msg.sender][op.sender] += 1;
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view override returns (bool) {
        return userOpState[id][multiplexer][account] != 0;
    }

    function isInitialized(address account, SessionId id) external view override returns (bool) {
        return userOpState[id][msg.sender][account] != 0;
    }

    function isInitialized(address account) external view override returns (bool) {
        revert("Not implemented");
    }

    function isInitialized(address multiplexer, address account) external view override returns (bool) {
        revert("Not implemented");
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }
}
