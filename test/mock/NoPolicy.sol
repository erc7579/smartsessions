// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import "contracts/lib/SubModuleLib.sol";

contract NoPolicy is IActionPolicy {
    using SubModuleLib for bytes;

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => uint256 calls))) public
        actionState;

    function onInstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        actionState[id][msg.sender][msg.sender] = 1;
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        actionState[configId][msg.sender][account] = 1;
    }

    function onUninstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        actionState[id][msg.sender][msg.sender] = 0;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_ACTION_POLICY;
    }

    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns (uint256)
    {
        actionState[id][msg.sender][account] += 1;
        return 1; // sig validation failed
    }

    function isInitialized(address account, ConfigId id) external view override returns (bool) {
        return actionState[id][account][account] != 0;
    }

    function isInitialized(address account, address multiplexer, ConfigId id) external view override returns (bool) {
        return actionState[id][multiplexer][account] != 0;
    }

    function isInitialized(address account) external view override returns (bool) { }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }

}
