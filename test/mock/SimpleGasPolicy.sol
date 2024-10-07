// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";

contract SimpleGasPolicy is IUserOpPolicy {

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

    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        gasLimitConfigs[configId][msg.sender][account].gasLimit = uint256(bytes32(initData[0:32]));
        gasLimitConfigs[configId][msg.sender][account].gasUsed = 0;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}
