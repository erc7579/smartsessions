// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/interfaces/IPolicy.sol";
import { CallType, CALLTYPE_BATCH, CALLTYPE_SINGLE, CALLTYPE_DELEGATECALL } from "erc7579/lib/ModeLib.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { ExecutionLib } from "contracts/lib/ExecutionLib.sol";

/**
 * @title ValueLimitPolicy
 * @notice A policy that limits the total amount of value that can be transferred within a permission.
 * @dev This is Action Policy as well as UserOp Policy. So the separate limit can be set for each action
 * in a permission or for all userOps in a permission.
 */
contract ValueLimitPolicy is IActionPolicy, IUserOpPolicy {
    using ExecutionLib for bytes;

    struct ValueLimitConfig {
        uint256 valueLimit;
        uint256 limitUsed;
    }

    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => ValueLimitConfig))) public
        valueLimitConfigs;

    /**
     * @notice Checks if the value limit is not exceeded by a given user operation.
     * @param id The config ID.
     * @param op The user operation.
     * @return The validation result.
     */
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata op) external returns (uint256) {
        ValueLimitConfig storage $config = valueLimitConfigs[id][msg.sender][op.sender];
        bytes4 selector = bytes4(op.callData[0:4]);
        if (selector == IERC7579Account.execute.selector) {
            (CallType callType,) = op.callData.get7579ExecutionTypes();
            if (callType == CALLTYPE_SINGLE) {
                (, uint256 value,) = op.callData.decodeUserOpCallData().decodeSingle();
                if (!_checkAndAdjustLimit($config, value)) return VALIDATION_FAILED;
            } else if (callType == CALLTYPE_BATCH) {
                Execution[] calldata executions = op.callData.decodeUserOpCallData().decodeBatch();
                uint256 length = executions.length;
                uint256 totalValue = 0;
                for (uint256 i; i < length; i++) {
                    totalValue += executions[i].value;
                }
                if (!_checkAndAdjustLimit($config, totalValue)) return VALIDATION_FAILED;
            } else {
                // CALLTYPE_STATIC and CALLTYPE_DELEGATECALL are not supported
                // it doesn't return validation failed to express that validation was not possible
                revert ISmartSession.UnsupportedCallType(callType);
            }
        }
        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Checks if the value limit is not exceeded by a given action.
     * @param id The config ID.
     * @param account The account.
     * @param value The value.
     * @return The validation result.
     */
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata
    )
        external
        returns (uint256)
    {
        ValueLimitConfig storage $config = valueLimitConfigs[id][msg.sender][account];
        if (!_checkAndAdjustLimit($config, value)) return VALIDATION_FAILED;
        return VALIDATION_SUCCESS;
    }

    /**
     * @notice Internal method to check if the limit is not exceeded and adjust the limit if it is not.
     * @param $config The value limit config.
     * @param value The value.
     * @return The result.
     */
    function _checkAndAdjustLimit(ValueLimitConfig storage $config, uint256 value) internal returns (bool) {
        if ($config.limitUsed + value > $config.valueLimit) return false;
        $config.limitUsed += value;
        return true;
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
        uint256 valueLimit = uint256(bytes32(initData[0:32]));
        require(valueLimit != 0, PolicyNotInitialized(configId, msg.sender, account));
        valueLimitConfigs[configId][msg.sender][account].valueLimit = valueLimit;
        valueLimitConfigs[configId][msg.sender][account].limitUsed = 0;
    }

    /**
     * @notice Returns the used limit.
     * @param configId The config ID.
     * @param msgSender The multiplexer.
     * @param userOpSender The user operation sender.
     * @return The used limit.
     */
    function getUsed(ConfigId configId, address msgSender, address userOpSender) external view returns (uint256) {
        return valueLimitConfigs[configId][msgSender][userOpSender].limitUsed;
    }

    /**
     * @notice Returns the value limit.
     * @param configId The config ID.
     * @param msgSender The multiplexer.
     * @param userOpSender The user operation sender.
     * @return The value limit.
     */
    function getValueLimit(
        ConfigId configId,
        address msgSender,
        address userOpSender
    )
        external
        view
        returns (uint256)
    {
        return valueLimitConfigs[configId][msgSender][userOpSender].valueLimit;
    }

    /**
     * @notice Checks if the interface is supported. Returns true if the interface is supported, false otherwise.
     * @param interfaceID The interface ID.
     * @return The result.
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
            || interfaceID == type(IActionPolicy).interfaceId || interfaceID == type(IUserOpPolicy).interfaceId;
    }
}
