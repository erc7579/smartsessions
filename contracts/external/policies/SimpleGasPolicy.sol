// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";

/**
 * @title SimpleGasPolicy
 * @notice A simple gas policy that allows to set an aggregate limit on the gas usage for a permission.
 * For every validate userOp, the gas used is accounted and summed up.
 * If the total gas that is about to be used by a current userOp together with what was already used, 
 * exceeds the limit, the userOp is reverted.
 * Notice: the gas which is accounted is not the gas that userOp ends up using, but the gas that is available 
 * for the userOp to use as per PackedUserOperation struct fields.
 */
contract SimpleGasPolicy is IUserOpPolicy {
    struct GasLimitConfig {
        uint256 gasLimit;
        uint256 gasUsed;
    }

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => GasLimitConfig))) public
        gasLimitConfigs;

    /**
     * @notice Checks if the user operation is valid according to the policy.
     * @param id The config ID.
     * @param userOp The user operation.
     * @return The validation result.
     */
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

    /**
     * @notice Initializes the policy for a given account through a multiplexer (msg.sender).
     * Overwrites state.
     * @notice ATTENTION: This method is called during permission installation as part of the enabling policies flow.
     * A secure policy would minimize external calls from this method (ideally, to 0) to prevent passing control flow to
     * external contracts.
     * @param account The account address.
     * @param configId The config ID.
     * @param initData The initialization data.
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        gasLimitConfigs[configId][msg.sender][account].gasLimit = uint256(bytes32(initData[0:32]));
        gasLimitConfigs[configId][msg.sender][account].gasUsed = 0;
    }

    /**
     * @notice Returns the gas limit
     * @param configId The config ID.
     * @param multiplexer The multiplexer address.
     * @param userOpSender The user operation sender address.
     * @return The gas limit.
     */
    function getGasLimit(ConfigId configId, address multiplexer, address userOpSender) external view returns (uint256) {
        return gasLimitConfigs[configId][multiplexer][userOpSender].gasLimit;
    }

    /**
     * @notice Returns the gas used 
     * @param configId The config ID.
     * @param multiplexer The multiplexer address.
     * @param userOpSender The user operation sender address.
     * @return The gas used.
     */
    function getGasUsed(ConfigId configId, address multiplexer, address userOpSender) external view returns (uint256) {
        return gasLimitConfigs[configId][multiplexer][userOpSender].gasUsed;
    }

    /**
     * @notice Supports the IERC165 interface.
     * @param interfaceID The interface ID.
     * @return True if the interface is supported, false otherwise.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}
