// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";

contract SimpleGasPolicy is IUserOpPolicy {

    struct GasLimitConfig {
        uint256 gasLimit;
        uint256 gasUsed;
    }

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => GasLimitConfig))) public
        gasLimitConfigs;

    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external returns (uint256) {
        GasLimitConfig storage config = gasLimitConfigs[id][msg.sender][userOp.sender];
        require(config.gasLimit > 0, PolicyNotInitialized(id, msg.sender, userOp.sender));
        
        uint256 totalUserOpGasLimit = 
            uint128(bytes16(userOp.accountGasLimits)) + // validation gas limit
            uint128(uint256(userOp.accountGasLimits)) + // call gas limit
            userOp.preVerificationGas; // pre verification gas

        // paymasterAndData structure: 
        // 20 bytes paymaster address
        // 16 bytes paymasterVerificationGasLimit
        // 16 bytes postOp gas limit
        // extra data 
        if (userOp.paymasterAndData.length >= 36) {
            totalUserOpGasLimit += uint128(bytes16(userOp.paymasterAndData[20:36])); // paymasterVerificationGasLimit
        }
        if (userOp.paymasterAndData.length >= 52) {
            totalUserOpGasLimit += uint128(bytes16(userOp.paymasterAndData[36:52])); // postOp gas limit
        }

        if (config.gasUsed + totalUserOpGasLimit > config.gasLimit) {
            return VALIDATION_FAILED;
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

    function getGasLimit(ConfigId configId, address multiplexer, address userOpSender) external view returns (uint256) {
        return gasLimitConfigs[configId][multiplexer][userOpSender].gasLimit;
    }

    function getGasUsed(ConfigId configId, address multiplexer, address userOpSender) external view returns (uint256) {
        return gasLimitConfigs[configId][multiplexer][userOpSender].gasUsed;
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}
