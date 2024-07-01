// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import {
    IUserOpPolicy, IActionPolicy, PackedUserOperation, VALIDATION_SUCCESS
} from "contracts/interfaces/IPolicies.sol";
import { TrustedForwarder } from "contracts/utils/TrustedForwarders.sol";

/*
    Since this policy increments .used on every check,
    malicious actor could grief the contract by calling those checks,
    so we have to only allow the checks to be called by the authorized SA
    That is achieved by inheriting TrustedForwarder
*/

enum Status {
    NA,
    Live,
    Deprecated
}

struct UsageLimitConfig {
    uint256 limit;
    uint256 used;
}

contract UsageLimitPolicy is IUserOpPolicy, IActionPolicy, TrustedForwarder {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 id => mapping(address => Status)) public status;
    mapping(bytes32 signerId => mapping(address smartAccount => UsageLimitConfig)) public usageLimitConfigs;

    function checkUserOp(bytes32 id, PackedUserOperation calldata userOp) external returns (uint256) {
        return _checkUsageLimit(id, _getAccount());
    }

    function checkAction(
        bytes32 id,
        address,
        uint256,
        bytes calldata,
        PackedUserOperation calldata userOp
    )
        external
        returns (uint256)
    {
        return _checkUsageLimit(id, _getAccount());
    }

    function _checkUsageLimit(bytes32 id, address smartAccount) internal returns (uint256) {
        require(status[id][smartAccount] == Status.Live);
        UsageLimitConfig storage config = usageLimitConfigs[id][smartAccount];
        if (config.limit == 0) {
            revert("UsageLimitPolicy: policy not installed");
        }
        if (++config.used > config.limit) {
            revert("UsageLimitPolicy: usage limit exceeded");
        }
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(bytes32 id, bytes calldata _data) internal {
        address smartAccount = _getAccount();
        require(status[id][smartAccount] == Status.NA);
        usedIds[smartAccount]++;
        status[id][smartAccount] = Status.Live;
        usageLimitConfigs[id][smartAccount].limit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(bytes32 id, bytes calldata) internal {
        address smartAccount = _getAccount();
        require(status[id][smartAccount] == Status.Live);
        status[id][smartAccount] = Status.Deprecated;
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
