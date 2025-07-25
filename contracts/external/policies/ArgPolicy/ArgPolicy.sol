// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Interfaces
import { IActionPolicy, IPolicy, VALIDATION_SUCCESS, VALIDATION_FAILED } from "../../../interfaces/IPolicy.sol";
import { IERC165 } from "forge-std/interfaces/IERC165.sol";

// Libraries
import { SubModuleLib } from "../../../lib/SubModuleLib.sol";
import { ArgPolicyTreeLib } from "./lib/ArgPolicyTreeLib.sol";

// Types
import { ConfigId, ActionData, PolicyData, PermissionId } from "../../../DataTypes.sol";

/*//////////////////////////////////////////////////////////////
                            STRUCTS
//////////////////////////////////////////////////////////////*/

/// @title ActionConfig - Configuration structure for ArgPolicy
/// @notice Stores the value limit and parameter rules for a policy
/// @param valueLimitPerUse Maximum value allowed per action
/// @param paramRules Rules and expression tree for evaluation
struct ActionConfig {
    uint256 valueLimitPerUse;
    ParamRules paramRules;
}

/// @title ParamRules - Container for rules and expression tree
/// @notice Stores the rules and their logical relationships
/// @param rootNodeIndex Index of the root node in the expression tree
/// @param rules Actual parameter rules
/// @param packedNodes Bit-packed nodes of the expression tree
struct ParamRules {
    uint8 rootNodeIndex;
    ParamRule[] rules;
    uint256[] packedNodes;
}

/// @title ParamRule - Rule for checking a parameter in the calldata
/// @notice Defines a condition to check against a parameter in calldata
/// @param condition Type of condition to check
/// @param offset Offset in calldata to read parameter (bytes)
/// @param isLimited Whether this parameter has a usage limit
/// @param ref Reference value to compare against
/// @param usage Limit information if isLimited is true
struct ParamRule {
    ParamCondition condition;
    uint64 offset;
    bool isLimited;
    bytes32 ref;
    LimitUsage usage;
}

/// @title LimitUsage - Tracks usage limits for parameters
/// @notice Maintains a counter against a maximum allowed value
/// @param limit Maximum allowed cumulative value
/// @param used Amount used so far
struct LimitUsage {
    uint256 limit;
    uint256 used;
}

/*//////////////////////////////////////////////////////////////
                            ENUMS
/////////////////////////////////////////////////////////////*/

/// @title ParamCondition - Types of conditions for parameter rules
/// @notice Enumeration of comparison operations
enum ParamCondition {
    EQUAL, // Parameter == ref
    GREATER_THAN, // Parameter > ref
    LESS_THAN, // Parameter < ref
    GREATER_THAN_OR_EQUAL, // Parameter >= ref
    LESS_THAN_OR_EQUAL, // Parameter <= ref
    NOT_EQUAL, // Parameter != ref
    IN_RANGE // ref is packed min/max, Parameter is within range

}

/**
 * @title ArgPolicy: Argument Policy
 * @author highskore
 * @notice A policy that allows defining complex logical expressions for calldata argument validation
 * @dev Implements a flexible rule system for validating function arguments in calldata using a tree-based
 *      logical expression evaluator that supports AND, OR, NOT operations with arbitrary nesting.
 *
 * The policy enables sophisticated argument validation with expressions like:
 * - (rule1 OR rule2) AND rule3
 * - rule1 AND (NOT rule2)
 * - (rule1 OR rule2) AND (rule3 OR (NOT rule4))
 *
 * Each rule can check a specific argument in the calldata against various conditions
 * (equality, ranges, thresholds) and can also enforce usage limits on arguments.
 */
contract ArgPolicy is IActionPolicy {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using SubModuleLib for bytes;
    using ArgPolicyTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when a value exceeds the allowed limit
    error ValueLimitExceeded(ConfigId id, uint256 value, uint256 limit);

    /*//////////////////////////////////////////////////////////////
                                 STATE
    //////////////////////////////////////////////////////////////*/

    /// @notice Maps config IDs and addresses to their action configurations
    /// @dev ConfigId => multiplexer address => user account => ActionConfig
    mapping(ConfigId id => mapping(address msgSender => mapping(address userOpSender => ActionConfig))) public
        actionConfigs;

    /**
     * @notice Checks if an action is allowed based on the configured rules
     * @dev Evaluates the expression tree to determine if the action is valid
     * @param id The configuration ID
     * @param account The account performing the action
     * @param value The ETH value being sent
     * @param data The calldata of the action
     * @return Validation result code (VALIDATION_SUCCESS or VALIDATION_FAILED)
     */
    function checkAction(
        ConfigId id,
        address account,
        address,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256)
    {
        ActionConfig storage config = actionConfigs[id][msg.sender][account];

        // Check if policy is initialized
        if (config.paramRules.rules.length == 0 || config.paramRules.packedNodes.length == 0) {
            revert PolicyNotInitialized(id, msg.sender, account);
        }

        // Check value limit
        if (value > config.valueLimitPerUse) {
            revert ValueLimitExceeded(id, value, config.valueLimitPerUse);
        }

        // Evaluate the expression tree
        bool result = config.paramRules.evaluateExpressionTree(data);
        return result ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    /**
     * @notice Initializes the policy with configuration data
     * @dev Validates and stores the configuration
     * @param id Configuration ID
     * @param mxer The multiplexer address
     * @param opSender The transaction sender
     * @param _data Encoded ActionConfig data
     */
    function _initPolicy(ConfigId id, address mxer, address opSender, bytes calldata _data) internal {
        ActionConfig memory config = abi.decode(_data, (ActionConfig));

        // Validate the expression tree
        ArgPolicyTreeLib.validateExpressionTree(config.paramRules);

        // Fill the storage with the provided config
        actionConfigs[id][mxer][opSender].fill(config);
    }

    /**
     * @notice Initializes the policy to be used by given account through multiplexer
     * @dev Overwrites any existing state
     * @param account The account that will use this policy
     * @param configId The configuration ID
     * @param initData Encoded initialization data (ActionConfig)
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external {
        _initPolicy(configId, msg.sender, account, initData);
        emit IPolicy.PolicySet(configId, msg.sender, account);
    }

    /**
     * @notice Checks if this contract supports a given interface
     * @dev Implements IERC165
     * @param interfaceID The interface identifier
     * @return True if supported, false otherwise
     */
    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return (
            interfaceID == type(IERC165).interfaceId || interfaceID == type(IPolicy).interfaceId
                || interfaceID == type(IActionPolicy).interfaceId
        );
    }
}
