// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { IUserOpPolicy, PackedUserOperation, VALIDATION_SUCCESS } from "contracts/interfaces/IPolicies.sol";

contract UsageLimitPolicy is IUserOpPolicy {

    struct UsageLimitConfig {
        uint256 limit;
        uint256 used;
    }

    mapping(address => uint256) public usedIds;
    mapping(bytes32 signerId => mapping(address smartAccount => UsageLimitConfig)) public usageLimitConfigs;

    function checkUserOp(bytes32 id, PackedUserOperation calldata userOp)
        external
        returns (uint256) 
    {
        UsageLimitConfig storage config = usageLimitConfigs[id][userOp.sender];
        if (++config.used > config.limit) {
            revert("UsageLimitPolicy: usage limit exceeded");
        }
        return VALIDATION_SUCCESS;    
    }

    function _onInstallPolicy(bytes32 id, bytes calldata _data) internal {
        address smartAccount = msg.sender/*_getAccount(signerId)*/;
        require(usageLimitConfigs[id][smartAccount].limit == 0);
        usedIds[smartAccount]++;
        usageLimitConfigs[id][smartAccount].limit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(bytes32 id, bytes calldata) internal {
        address smartAccount = msg.sender /*_getAccount(signerId)*/;
        require(usageLimitConfigs[id][smartAccount].limit != 0);
        delete usageLimitConfigs[id][smartAccount];
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
        return id == 222;
    }

}

