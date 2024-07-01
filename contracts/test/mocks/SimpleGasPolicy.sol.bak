// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { IUserOpPolicy, PackedUserOperation, VALIDATION_SUCCESS } from "contracts/interfaces/IPolicies.sol";
import { TrustedForwarder } from "contracts/utils/TrustedForwarders.sol";

contract SimpleGasPolicy is IUserOpPolicy, TrustedForwarder {
    struct UsageLimitConfig {
        uint256 gasLimit;
        uint256 gasUsed;
    }

    mapping(address => uint256) public usedIds;
    mapping(bytes32 signerId => mapping(address smartAccount => UsageLimitConfig)) public usageLimitConfigs;

    function checkUserOp(bytes32 id, PackedUserOperation calldata userOp) external returns (uint256) {
        UsageLimitConfig storage config = usageLimitConfigs[id][_getAccount()];
        if (config.gasLimit == 0) {
            revert("UsageLimitPolicy: policy not installed");
        }
        uint256 totalUserOpGasLimit = uint128(bytes16(userOp.accountGasLimits))
            + uint128(uint256(userOp.accountGasLimits)) + userOp.preVerificationGas;
        if (config.gasUsed + totalUserOpGasLimit > config.gasLimit) {
            revert("UsageLimitPolicy: usage limit exceeded");
        }

        // Limit will be quite accurate as per AA-217
        // https://github.com/eth-infinitism/account-abstraction/pull/356
        config.gasUsed += totalUserOpGasLimit;
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(bytes32 id, bytes calldata _data) internal {
        address smartAccount = _getAccount();
        require(usageLimitConfigs[id][smartAccount].gasLimit == 0);
        usedIds[smartAccount]++;
        usageLimitConfigs[id][smartAccount].gasLimit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(bytes32 id, bytes calldata) internal {
        address smartAccount = _getAccount();
        require(usageLimitConfigs[id][smartAccount].gasLimit != 0);
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
