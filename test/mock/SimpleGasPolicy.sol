// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "contracts/lib/SubLib.sol";

contract SimpleGasPolicy is IUserOpPolicy {
    
    using SubLib for bytes;

    struct UsageLimitConfig {
        uint256 gasLimit;
        uint256 gasUsed;
    }

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => UsageLimitConfig))) public usageLimitConfigs;

    function checkUserOpPolicy(SessionId id, PackedUserOperation calldata userOp) external returns (uint256) {
        UsageLimitConfig storage config = usageLimitConfigs[id][msg.sender][userOp.sender];
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

    function _onInstallPolicy(SessionId id, address opSender, bytes calldata _data) internal {
        require(usageLimitConfigs[id][msg.sender][opSender].gasLimit == 0);
        usedIds[msg.sender][opSender]++;
        usageLimitConfigs[id][msg.sender][opSender].gasLimit = uint256(bytes32(_data[0:32]));
    }

    function _onUninstallPolicy(SessionId id, address opSender, bytes calldata) internal {
        require(usageLimitConfigs[id][msg.sender][opSender].gasLimit != 0);
        delete usageLimitConfigs[id][msg.sender][opSender];
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
        return id == 222; //userOpPolicy
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view override returns (bool) {
        return usageLimitConfigs[id][multiplexer][account].gasLimit > 0;
    }

    function isInitialized(address account, SessionId id) external view override returns (bool) {
        return usageLimitConfigs[id][msg.sender][account].gasLimit > 0;
    }

    function isInitialized(address multiplexer, address account) external view override returns (bool) {
        return usedIds[multiplexer][account] > 0;
    }

    function isInitialized(address account) external view override returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }
}
