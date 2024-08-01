// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubLib.sol";

contract ValueLimitPolicy is IActionPolicy {
    using SubLib for bytes;

    struct ValueLimitConfig {
        uint256 valueLimit;
        uint256 limitUsed;
    }

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => ValueLimitConfig))) public
        valueLimitConfigs;

    // TODO: Make per SignerId limits => this will allow to set value transfer limits not per action, but per session
    // key (signer)
    // To make this, need to make one more mapping
    // mapping(SignerId signerId => mapping(address msgSender => mapping(address userOpSender => ValueLimitConfig)))
    // public valueLimitConfigs;
    // and receive this limit in onInstall
    // and use EncodeLib.getSignerIdFromSignature() method to get signerId from op.signature
    // and check/increment value limits and usage per SignerId as well
    // so there can be no checking limits per action (need to set let's say 0xfefefefefefe as valueLimit to avoid check
    // and increment)
    // but check per signerId

    function checkAction(
        SessionId id,
        address,
        uint256 value,
        bytes calldata callData,
        PackedUserOperation calldata op
    )
        external
        returns (uint256)
    {
        ValueLimitConfig storage config = valueLimitConfigs[id][msg.sender][op.sender];
        if (config.valueLimit == 0) {
            revert("ValueLimitPolicy: config not installed");
        }
        if (config.limitUsed + value > config.valueLimit) {
            revert("ValueLimitPolicy: limit exceeded");
        }
        config.limitUsed += value;
        return VALIDATION_SUCCESS;
    }

    function _onInstallPolicy(SessionId id, address opSender, bytes calldata _data) internal {
        require(valueLimitConfigs[id][msg.sender][opSender].valueLimit == 0);
        usedIds[msg.sender][opSender]++;
        valueLimitConfigs[id][msg.sender][opSender].valueLimit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(SessionId id, address opSender, bytes calldata) internal {
        require(valueLimitConfigs[id][msg.sender][opSender].valueLimit != 0);
        delete valueLimitConfigs[id][msg.sender][opSender];
        usedIds[msg.sender][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onInstallPolicy(id, opSender, _data);
    }

    function onUninstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onUninstallPolicy(id, opSender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 7;
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view override returns (bool) {
        return valueLimitConfigs[id][multiplexer][account].valueLimit > 0;
    }

    function isInitialized(address account, SessionId id) external view override returns (bool) {
        return valueLimitConfigs[id][msg.sender][account].valueLimit > 0;
    }

    function isInitialized(address multiplexer, address account) external view override returns (bool) {
        return usedIds[multiplexer][account] > 0;
    }

    function isInitialized(address account) external view override returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }
}
