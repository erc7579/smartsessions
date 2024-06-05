// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { IUserOpPolicy, IActionPolicy, PackedUserOperation, VALIDATION_SUCCESS } from "contracts/interfaces/IPolicies.sol";
import { _packValidationData } from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

import "forge-std/console2.sol";

// This submodule doesn't need to be TrustedForwarder as both checks are view

contract TimeFramePolicy is IUserOpPolicy, IActionPolicy {

    struct TimeFrameConfig {
        uint48 validUntil;
        uint48 validAfter;
    }

    mapping(address => uint256) public usedIds;
    mapping(bytes32 signerId => mapping(address smartAccount => TimeFrameConfig)) public timeFrameConfigs;

    function checkUserOp(bytes32 id, PackedUserOperation calldata userOp)
        external view
        returns (uint256) 
    {
        return _checkTimeFrame(id, userOp.sender);   
    }

    function checkAction(bytes32 id, address, uint256, bytes calldata, PackedUserOperation calldata userOp)
        external view
        returns (uint256) 
    {
        return _checkTimeFrame(id, userOp.sender);
    }

    function _checkTimeFrame(bytes32 id, address smartAccount) internal view returns (uint256) {
        TimeFrameConfig storage config = timeFrameConfigs[id][smartAccount];
        return _packValidationData(false, config.validUntil, config.validAfter);
    }

    function _onInstallPolicy(bytes32 id, bytes calldata _data) internal {
        address smartAccount = msg.sender;
        require(timeFrameConfigs[id][smartAccount].validUntil == 0 && timeFrameConfigs[id][smartAccount].validAfter == 0);
        usedIds[smartAccount]++;
        timeFrameConfigs[id][smartAccount].validUntil = uint48(uint128(bytes16(_data[0:16])));
        timeFrameConfigs[id][smartAccount].validAfter = uint48(uint128(bytes16(_data[16:32])));
    }

    function _onUninstallPolicy(bytes32 id, bytes calldata) internal {
        address smartAccount = msg.sender;
        require(timeFrameConfigs[id][smartAccount].validUntil != 0 || timeFrameConfigs[id][smartAccount].validAfter != 0);
        delete timeFrameConfigs[id][smartAccount];
        usedIds[smartAccount]--;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[smartAccount] > 0;
    }

    function onInstall(bytes calldata data) external {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _onInstallPolicy(id, _data);
    }

    function onUninstall(bytes calldata data) external {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _onUninstallPolicy(id, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 222 || id == 223;
    }

}

