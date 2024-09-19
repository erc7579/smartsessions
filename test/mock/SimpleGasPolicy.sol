// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubModuleLib.sol";

contract SimpleGasPolicy is IUserOpPolicy {
    using SubModuleLib for bytes;

    struct GasLimitConfig {
        uint256 gasLimit;
        uint256 gasUsed;
    }

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => GasLimitConfig))) public
        gasLimitConfigs;

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external returns (uint256) {
        GasLimitConfig storage config = gasLimitConfigs[id][msg.sender][userOp.sender];
        if (config.gasLimit == 0) {
            revert("GasLimitPolicy: policy not installed");
        }
        uint256 totalUserOpGasLimit = uint128(bytes16(userOp.accountGasLimits))
            + uint128(uint256(userOp.accountGasLimits)) + userOp.preVerificationGas;
        if (config.gasUsed + totalUserOpGasLimit > config.gasLimit) {
            revert("GasLimitPolicy: gas limit exceeded");
        }

        // Limit will be quite accurate as per AA-217
        // https://github.com/eth-infinitism/account-abstraction/pull/356
        config.gasUsed += totalUserOpGasLimit;
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata _data) internal {
        usedIds[mxer][opSender]++;
        gasLimitConfigs[id][mxer][opSender].gasLimit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata) internal {
        delete gasLimitConfigs[id][mxer][opSender];
        usedIds[mxer][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(gasLimitConfigs[id][msg.sender][msg.sender].gasLimit == 0);
        _onInstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        _onInstallPolicy(configId, msg.sender, account, initData);
    }

    function onUninstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(gasLimitConfigs[id][msg.sender][msg.sender].gasLimit != 0);
        _onUninstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7; //userOpPolicy
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
