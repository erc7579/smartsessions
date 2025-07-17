// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import "@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol";

/**
 * @title SimpleGasPolicy
 * @notice A simple gas policy that allows to set an aggregate limit on the gas usage for a permission.
 * For every validate userOp, the gas used is accounted and summed up.
 * If the total gas used exceeds the limit, the userOp validation fails. It also checks the cost limit
 * for the userOp, which is calculated as gas used multiplied by the actual gas price.
 * Notice: the gas which is accounted is not the gas that userOp ends up using, but the gas that is available
 * for the userOp to use as per PackedUserOperation struct fields.
 */
contract SimpleGasPolicy is IUserOpPolicy {
    struct GasLimitConfig {
        uint128 gasLimit; // Max gas units allowed
        uint128 gasUsed; // Gas units used so far
        uint128 costLimit; // Max cost (wei) allowed
        uint128 costUsed; // Total cost (wei) used so far
    }

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => GasLimitConfig))) internal
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

        uint256 totalUserOpGasLimit = UserOperationLib.unpackVerificationGasLimit(userOp) // validation gas limit
            + UserOperationLib.unpackCallGasLimit(userOp) // call gas limit
            + userOp.preVerificationGas; // pre verification gas

        // Add paymaster gas limits if paymaster is used
        if (userOp.paymasterAndData.length >= UserOperationLib.PAYMASTER_DATA_OFFSET) {
            totalUserOpGasLimit += UserOperationLib.unpackPaymasterVerificationGasLimit(userOp); // paymasterVerificationGasLimit
            totalUserOpGasLimit += UserOperationLib.unpackPostOpGasLimit(userOp); // postOp gas limit
        }

        // Calculate total cost for this operation using UserOperationLib
        uint256 actualGasPrice = UserOperationLib.gasPrice(userOp);
        uint256 totalUserOpCost = totalUserOpGasLimit * actualGasPrice;

        // Check both gas unit limit AND cost limit
        if (config.gasUsed + totalUserOpGasLimit > config.gasLimit) {
            return VALIDATION_FAILED;
        }

        if (config.costUsed + totalUserOpCost > config.costLimit) {
            return VALIDATION_FAILED;
        }

        // Update both gas units used and cost used (with overflow protection)
        config.gasUsed += uint128(totalUserOpGasLimit); // Safe cast since we checked limits above
        config.costUsed += uint128(totalUserOpCost); // Safe cast since we checked limits above

        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Initializes the policy for a given account through a multiplexer (msg.sender).
     * @param account The account address.
     * @param configId The config ID.
     * @param initData The initialization data (gasLimit in first 16 bytes, costLimit in next 16 bytes).
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        require(initData.length >= 32, PolicyNotInitialized(configId, msg.sender, account));

        // If either limit is zero, revert with InvalidInitDataLength
        uint128 gasLimit = uint128(bytes16(initData[0:16]));
        uint128 costLimit = uint128(bytes16(initData[16:32]));
        require(gasLimit != 0 && costLimit != 0, PolicyNotInitialized(configId, msg.sender, account));

        gasLimitConfigs[configId][msg.sender][account].gasLimit = gasLimit;
        gasLimitConfigs[configId][msg.sender][account].costLimit = costLimit;
        gasLimitConfigs[configId][msg.sender][account].gasUsed = 0;
        gasLimitConfigs[configId][msg.sender][account].costUsed = 0;
    }

    /**
     * @notice Returns the gas configuration
     * @param configId The config ID.
     * @param multiplexer The multiplexer address.
     * @param userOpSender The user operation sender address.
     * @return gasLimit The gas limit.
     * @return gasUsed The gas used.
     * @return costLimit The cost limit.
     * @return costUsed The cost used.
     */
    function getGasConfig(
        ConfigId configId,
        address multiplexer,
        address userOpSender
    )
        external
        view
        returns (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed)
    {
        GasLimitConfig storage config = gasLimitConfigs[configId][multiplexer][userOpSender];
        return (config.gasLimit, config.gasUsed, config.costLimit, config.costUsed);
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
