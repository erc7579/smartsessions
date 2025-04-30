// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Types
import { ParamRule, ParamRules, ActionConfig, ParamCondition } from "../ArgPolicy.sol";

/**
 * @title ArgPolicyTreeLib
 * @notice Library implementing the parameter rules validation and expression tree evaluation for ArgPolicy
 * @dev Contains functions for checking rules, evaluating expression trees, and manipulating nodes
 */
library ArgPolicyTreeLib {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when the expression tree is empty
    error EmptyExpressionTree();
    /// @notice Error thrown when the root node index is out of bounds
    error RootNodeIndexOutOfBounds();
    /// @notice Error thrown when there are too many rules
    error TooManyRules();
    /// @notice Error thrown when there are too many nodes
    error TooManyNodes();
    /// @notice Error thrown when a node child index is out of bounds
    error NodeChildIndexOutOfBounds();
    /// @notice Error thrown when a rule index is out of bounds
    error RuleIndexOutOfBounds();

    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using ArgPolicyTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // Node type constants
    uint8 constant NODE_TYPE_RULE = 0; // Leaf node referencing a rule
    uint8 constant NODE_TYPE_NOT = 1; // NOT operator (unary)
    uint8 constant NODE_TYPE_AND = 2; // AND operator (binary)
    uint8 constant NODE_TYPE_OR = 3; // OR operator (binary)

    // Bit positions and masks for the packed node format
    uint8 constant NODE_TYPE_SHIFT = 0;
    uint8 constant RULE_INDEX_SHIFT = 2;
    uint8 constant LEFT_CHILD_SHIFT = 10;
    uint8 constant RIGHT_CHILD_SHIFT = 18;

    uint256 constant NODE_TYPE_MASK = 0x3; // 2 bits
    uint256 constant RULE_INDEX_MASK = 0xFF; // 8 bits (rule index 0-255)
    uint256 constant LEFT_CHILD_MASK = 0xFF; // 8 bits (child index 0-255)
    uint256 constant RIGHT_CHILD_MASK = 0xFF; // 8 bits (child index 0-255)

    // Maximum number of rules and nodes
    uint256 constant MAX_RULES = 128; // Maximum number of rules
    uint256 constant MAX_NODES = 256; // Maximum number of nodes

    /*//////////////////////////////////////////////////////////////
                                VALIDATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Checks a single parameter rule against the calldata
     * @dev Extracts parameter from calldata and applies the rule's condition
     * @param rule The rule to check
     * @param data The calldata to check against
     * @return True if the rule passes, false otherwise
     */
    function check(ParamRule storage rule, bytes calldata data) internal returns (bool) {
        // Cache the offset
        uint64 offset = rule.offset;
        // Cache the condition
        ParamCondition condition = rule.condition;
        // Cache the reference value
        bytes32 ref = rule.ref;
        // Extract 32 bytes from calldata at the specified offset
        // First 4 bytes are the function selector, so we add 4 to the offset
        bytes32 param = bytes32(data[4 + offset:4 + offset + 32]);

        // CHECK Param Condition
        if (condition == ParamCondition.EQUAL && param != ref) {
            // Fails if parameter is not equal to reference value
            return false;
        } else if (condition == ParamCondition.GREATER_THAN && param <= ref) {
            // Fails if parameter is not greater than reference value
            return false;
        } else if (condition == ParamCondition.LESS_THAN && param >= ref) {
            // Fails if parameter is not less than reference value
            return false;
        } else if (condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < ref) {
            // Fails if parameter is not greater than or equal to reference value
            return false;
        } else if (condition == ParamCondition.LESS_THAN_OR_EQUAL && param > ref) {
            // Fails if parameter is not less than or equal to reference value
            return false;
        } else if (condition == ParamCondition.NOT_EQUAL && param == ref) {
            // Fails if parameter equals reference value (should be different)
            return false;
        } else if (condition == ParamCondition.IN_RANGE) {
            // For IN_RANGE condition, rule.ref contains both min and max values
            // rule.ref format: first 128 bits = min value, last 128 bits = max value
            if (
                param < (ref >> 128) // Check if param is less than min value (high 128 bits)
                    || param > (ref & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff) // Check if
                    // param is greater than max value (low 128 bits)
            ) {
                return false;
            }
        }

        // CHECK Param Limit
        if (rule.isLimited) {
            // Check if adding this parameter's value would exceed the defined usage limit
            if (rule.usage.used + uint256(param) > rule.usage.limit) {
                return false;
            }
            // Update the usage counter by adding the parameter value
            rule.usage.used += uint256(param);
        }
        return true;
    }

    /**
     * @notice Validates that the expression tree is properly formed
     * @dev Checks for valid indices and references
     * @param rules The ParamRules struct containing the expression tree
     */
    function validateExpressionTree(ParamRules memory rules) internal pure {
        // Cache length
        uint256 nodeCount = rules.packedNodes.length;
        uint256 ruleCount = rules.rules.length;

        // Check if the expression tree is empty
        require(nodeCount != 0, EmptyExpressionTree());
        // Check if the root node index is within bounds
        require(rules.rootNodeIndex < nodeCount, RootNodeIndexOutOfBounds());
        // Check if the number of rules exceeds the maximum allowed
        require(ruleCount <= MAX_RULES, TooManyRules());
        // Check if the number of nodes exceeds the maximum allowed
        require(nodeCount <= MAX_NODES, TooManyNodes());

        // Check each node in the tree
        for (uint8 i = 0; i < nodeCount; i++) {
            uint256 node = rules.packedNodes[i];
            uint8 nodeType = node.getNodeType();

            if (nodeType == NODE_TYPE_RULE) {
                // Rule nodes must reference a valid rule
                uint8 ruleIndex = node.getRuleIndex();
                // Check if the rule index is within bounds
                require(ruleIndex < ruleCount, RuleIndexOutOfBounds());
            } else if (nodeType == NODE_TYPE_NOT) {
                // NOT nodes must have a valid child
                uint8 childIndex = node.getLeftChildIndex();
                // Check if the child index is within bounds
                require(childIndex < nodeCount, NodeChildIndexOutOfBounds());
            } else {
                // AND or OR nodes
                // Must have valid left and right children
                uint8 leftChildIndex = node.getLeftChildIndex();
                uint8 rightChildIndex = node.getRightChildIndex();
                // Check if the left and right child indices are within bounds
                require(leftChildIndex < nodeCount && rightChildIndex < nodeCount, NodeChildIndexOutOfBounds());
            }
        }
    }

    /*//////////////////////////////////////////////////////////////
                                EVALUATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Evaluates the expression tree starting from the root node
     * @dev Entry point for tree evaluation
     * @param rules The ParamRules struct containing rules and expression tree
     * @param data The calldata to evaluate against
     * @return Result of the logical expression evaluation
     */
    function evaluateExpressionTree(ParamRules storage rules, bytes calldata data) internal returns (bool) {
        return evaluateNode(rules.packedNodes, rules.rootNodeIndex, rules.rules, data);
    }

    /**
     * @notice Evaluates a node in the expression tree
     * @dev Recursively evaluates nodes with short-circuit optimization
     * @param packedNodes Array of bit-packed nodes
     * @param nodeIndex Index of the current node to evaluate
     * @param rules Array of parameter rules
     * @param data The calldata to evaluate against
     * @return Result of evaluating this node and its children
     */
    function evaluateNode(
        uint256[] storage packedNodes,
        uint8 nodeIndex,
        ParamRule[] storage rules,
        bytes calldata data
    )
        internal
        returns (bool)
    {
        // Load the packed node from storage (single SLOAD operation)
        uint256 node = packedNodes[nodeIndex];

        // Extract node type
        uint8 nodeType = node.getNodeType();

        // Evaluate based on node type
        if (nodeType == NODE_TYPE_RULE) {
            // Extract rule index
            uint8 ruleIndex = node.getRuleIndex();
            return rules[ruleIndex].check(data);
        } else if (nodeType == NODE_TYPE_NOT) {
            // Extract child index
            uint8 childIndex = node.getLeftChildIndex();
            return !evaluateNode(packedNodes, childIndex, rules, data);
        } else if (nodeType == NODE_TYPE_AND) {
            // Extract left child index
            uint8 leftChildIndex = node.getLeftChildIndex();
            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);
            // Short-circuit: if left result is false, the AND result is false
            if (!leftResult) return false;
            // Extract right child index
            uint8 rightChildIndex = node.getRightChildIndex();
            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        } else if (nodeType == NODE_TYPE_OR) {
            // Extract left child index
            uint8 leftChildIndex = node.getLeftChildIndex();
            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);
            // Short-circuit: if left result is true, the OR result is true
            if (leftResult) return true;
            // Extract right child index
            uint8 rightChildIndex = node.getRightChildIndex();
            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        }

        // Should never reach here if the tree is valid
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                  FILL
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Fills the storage config with the provided memory config
     * @dev Uses the delete approach for simplicity and clean slate
     * @param $config The storage configuration to fill
     * @param config The memory configuration to copy from
     */
    function fill(ActionConfig storage $config, ActionConfig memory config) internal {
        // Set scalar values
        $config.valueLimitPerUse = config.valueLimitPerUse;
        $config.paramRules.rootNodeIndex = config.paramRules.rootNodeIndex;

        // Clear existing rules and packed nodes just in case
        delete $config.paramRules.rules;
        delete $config.paramRules.packedNodes;

        // Add new rules
        for (uint256 i = 0; i < config.paramRules.rules.length; i++) {
            $config.paramRules.rules.push(config.paramRules.rules[i]);
        }
        // Add new packed nodes
        for (uint256 i = 0; i < config.paramRules.packedNodes.length; i++) {
            $config.paramRules.packedNodes.push(config.paramRules.packedNodes[i]);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                HELPERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates a packed rule node
     * @dev Bit-packs a RULE type node with a rule index
     * @param ruleIndex Index of the rule this node references
     * @return Packed node data
     */
    function createRuleNode(uint8 ruleIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_RULE) | (uint256(ruleIndex) << RULE_INDEX_SHIFT);
    }

    /**
     * @notice Creates a packed NOT node
     * @dev Bit-packs a NOT type node with a child index
     * @param childIndex Index of the child node
     * @return Packed node data
     */
    function createNotNode(uint8 childIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_NOT) | (uint256(childIndex) << LEFT_CHILD_SHIFT);
    }

    /**
     * @notice Creates a packed AND node
     * @dev Bit-packs an AND type node with left and right child indices
     * @param leftChildIndex Index of the left child node
     * @param rightChildIndex Index of the right child node
     * @return Packed node data
     */
    function createAndNode(uint8 leftChildIndex, uint8 rightChildIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_AND) | (uint256(leftChildIndex) << LEFT_CHILD_SHIFT)
            | (uint256(rightChildIndex) << RIGHT_CHILD_SHIFT);
    }

    /**
     * @notice Creates a packed OR node
     * @dev Bit-packs an OR type node with left and right child indices
     * @param leftChildIndex Index of the left child node
     * @param rightChildIndex Index of the right child node
     * @return Packed node data
     */
    function createOrNode(uint8 leftChildIndex, uint8 rightChildIndex) internal pure returns (uint256) {
        return uint256(NODE_TYPE_OR) | (uint256(leftChildIndex) << LEFT_CHILD_SHIFT)
            | (uint256(rightChildIndex) << RIGHT_CHILD_SHIFT);
    }

    /**
     * @notice Extracts the node type from a packed node
     * @dev Applies mask to get the node type bits
     * @param packedNode The packed node data
     * @return Node type (RULE, NOT, AND, or OR)
     */
    function getNodeType(uint256 packedNode) internal pure returns (uint8) {
        return uint8(packedNode & NODE_TYPE_MASK);
    }

    /**
     * @notice Extracts the rule index from a packed node
     * @dev Shifts and masks to get the rule index bits
     * @param packedNode The packed node data
     * @return Rule index
     */
    function getRuleIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> RULE_INDEX_SHIFT) & RULE_INDEX_MASK);
    }

    /**
     * @notice Extracts the left child index from a packed node
     * @dev Shifts and masks to get the left child index bits
     * @param packedNode The packed node data
     * @return Left child index
     */
    function getLeftChildIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);
    }

    /**
     * @notice Extracts the right child index from a packed node
     * @dev Shifts and masks to get the right child index bits
     * @param packedNode The packed node data
     * @return Right child index
     */
    function getRightChildIndex(uint256 packedNode) internal pure returns (uint8) {
        return uint8((packedNode >> RIGHT_CHILD_SHIFT) & RIGHT_CHILD_MASK);
    }
}
