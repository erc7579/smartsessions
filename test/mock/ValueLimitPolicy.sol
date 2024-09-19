// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubModuleLib.sol";

contract ValueLimitPolicy is IActionPolicy {
    using SubModuleLib for bytes;

    struct ValueLimitConfig {
        uint256 valueLimit;
        uint256 limitUsed;
    }

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => ValueLimitConfig))) public
        valueLimitConfigs;

    // TODO: Make per PermissionId limits => this will allow to set value transfer limits not per action, but per
    // session
    // key (signer)
    // To make this, need to make one more mapping
    // mapping(PermissionId permissionId => mapping(address msgSender => mapping(address userOpSender =>
    // ValueLimitConfig)))
    // public valueLimitConfigs;
    // and receive this limit in onInstall
    // and use EncodeLib.getPermissionIdFromSignature() method to get permissionId from op.signature
    // and check/increment value limits and usage per PermissionId as well
    // so there can be no checking limits per action (need to set let's say 0xfefefefefefe as valueLimit to avoid check
    // and increment)
    // but check per permissionId

    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata callData
    )
        external
        returns (uint256)
    {
        ValueLimitConfig storage config = valueLimitConfigs[id][msg.sender][account];
        if (config.valueLimit == 0) {
            revert("ValueLimitPolicy: config not installed");
        }
        if (config.limitUsed + value > config.valueLimit) {
            revert("ValueLimitPolicy: limit exceeded");
        }
        config.limitUsed += value;
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata _data) internal {
        usedIds[mxer][opSender]++;
        valueLimitConfigs[id][mxer][opSender].valueLimit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(ConfigId id, address mxer, address opSender, bytes calldata) internal {
        delete valueLimitConfigs[id][mxer][opSender];
        usedIds[mxer][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(valueLimitConfigs[id][msg.sender][msg.sender].valueLimit == 0);
        _onInstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        _onInstallPolicy(configId, msg.sender, account, initData);
    }

    function onUninstall(bytes calldata data) external {
        (ConfigId id, bytes calldata _data) = data.parseInstallData();
        require(valueLimitConfigs[id][msg.sender][msg.sender].valueLimit != 0);
        _onUninstallPolicy(id, msg.sender, msg.sender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 8;
    }

    // function isInitialized(address account, address multiplexer, ConfigId id) external view override returns (bool) {
    //     return valueLimitConfigs[id][multiplexer][account].valueLimit > 0;
    // }
    //
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
