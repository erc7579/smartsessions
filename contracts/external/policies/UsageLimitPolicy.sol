// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";

/**
 * @title UsageLimitPolicy
 * @notice A policy that limits the total amount of actions/userOps that can be performed within a permission.
 */
contract UsageLimitPolicy is IUserOpPolicy, IActionPolicy {
    struct UsageLimitConfig {
        uint128 limit;
        uint128 used;
    }

    mapping(ConfigId id => mapping(address multiplexer => mapping(address userOpSender => UsageLimitConfig))) public
        usageLimitConfigs;

    /**
     * @notice Checks if the limit is not exceeded.
     * @param id The config ID.
     * @param op The user operation.
     * @return The validation result.
     */
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata op) external returns (uint256) {
        return _checkUsageLimit(id, msg.sender, op.sender);
    }

    /**
     * @notice Checks if the limit is not exceeded.
     * @param id The config ID.
     * @param account The account.
     * @return The validation result.
     */
    function checkAction(ConfigId id, address account, address, uint256, bytes calldata) external returns (uint256) {
        return _checkUsageLimit(id, msg.sender, account);
    }

    /**
     * @notice Internal method to check if the limit is not exceeded.
     * @param id The config ID.
     * @param mxer The multiplexer.
     * @param smartAccount The smart account.
     * @return The validation result.
     */
    function _checkUsageLimit(ConfigId id, address mxer, address smartAccount) internal returns (uint256) {
        UsageLimitConfig storage $config = usageLimitConfigs[id][mxer][smartAccount];
        uint128 limit = $config.limit;
        uint128 newUsed = $config.used += 1; // Increment the used count
        if (newUsed > limit) {
            return VALIDATION_FAILED;
        }
        // Update the used count in the mapping
        $config.used = newUsed;
        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Initializes the policy to be used by given account through multiplexer (msg.sender) such as Smart
     * Sessions.
     * Overwrites state.
     * @notice ATTENTION: This method is called during permission installation as part of the enabling policies flow.
     * A secure policy would minimize external calls from this method (ideally, to 0) to prevent passing control flow to
     * external contracts.
     * @param account The account.
     * @param configId The config ID.
     * @param initData The initialization data.
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        uint128 limit = uint128(bytes16(initData[0:16]));
        require(limit != 0, PolicyNotInitialized(configId, msg.sender, account));
        usageLimitConfigs[configId][msg.sender][account].limit = limit;
        usageLimitConfigs[configId][msg.sender][account].used = 0;
    }

    /**
     * @notice Returns the limit.
     * @param id The config ID.
     * @param mxer The multiplexer.
     * @param smartAccount The smart account.
     */
    function getUsageLimit(ConfigId id, address mxer, address smartAccount) external view returns (uint128 limit) {
        return usageLimitConfigs[id][mxer][smartAccount].limit;
    }

    /**
     * @notice Returns the used limit.
     * @param id The config ID.
     * @param mxer The multiplexer.
     * @param smartAccount The smart account.
     */
    function getUsed(ConfigId id, address mxer, address smartAccount) external view returns (uint128 used) {
        return usageLimitConfigs[id][mxer][smartAccount].used;
    }

    /**
     * @notice Checks if the interface is supported.
     * @param interfaceID The interface ID.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IUserOpPolicy).interfaceId || interfaceID == type(IActionPolicy).interfaceId;
    }
}
