// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

// Types
import { ParamRule, ParamRules, ActionConfig, ParamCondition } from "../UniActionPolicyV2.sol";

/**
 * @title UniActionTreeLib
 * @notice Library implementing the parameter rules validation and expression tree evaluation for UniActionPolicyV2
 * @dev Contains functions for checking rules, evaluating expression trees, and manipulating nodes
 */
library UniActionTreeLib {
    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    /// @notice Error thrown when the expression tree has an invalid structure
    error InvalidExpressionTree(string reason);

    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using UniActionTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    // Node type constants - only need 2 bits
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
        bytes32 param = bytes32(data[4 + rule.offset:4 + rule.offset + 32]);

        // CHECK Param Condition
        if (rule.condition == ParamCondition.EQUAL && param != rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.GREATER_THAN && param <= rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.LESS_THAN && param >= rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.GREATER_THAN_OR_EQUAL && param < rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.LESS_THAN_OR_EQUAL && param > rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.NOT_EQUAL && param == rule.ref) {
            return false;
        } else if (rule.condition == ParamCondition.IN_RANGE) {
            // in this case rule.ref is abi.encodePacked(uint128(min), uint128(max))
            if (
                param < (rule.ref >> 128)
                    || param > (rule.ref & 0x00000000000000000000000000000000ffffffffffffffffffffffffffffffff)
            ) {
                return false;
            }
        }

        // CHECK Param Limit
        if (rule.isLimited) {
            if (rule.usage.used + uint256(param) > rule.usage.limit) {
                return false;
            }
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
        if (rules.nodeCount == 0) {
            revert InvalidExpressionTree("Empty expression tree");
        }

        if (rules.rootNodeIndex >= rules.nodeCount) {
            revert InvalidExpressionTree("Root node index out of bounds");
        }

        // Check each node in the tree
        for (uint8 i = 0; i < rules.nodeCount; i++) {
            uint256 node = rules.packedNodes[i];
            uint8 nodeType = uint8(node & NODE_TYPE_MASK);

            if (nodeType == NODE_TYPE_RULE) {
                // Rule nodes must reference a valid rule
                uint8 ruleIndex = uint8((node >> RULE_INDEX_SHIFT) & RULE_INDEX_MASK);
                if (ruleIndex >= rules.ruleCount) {
                    revert InvalidExpressionTree("Rule index out of bounds");
                }
            } else if (nodeType == NODE_TYPE_NOT) {
                // NOT nodes must have a valid child
                uint8 childIndex = uint8((node >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);
                if (childIndex >= rules.nodeCount) {
                    revert InvalidExpressionTree("NOT node child index out of bounds");
                }
            } else {
                // AND or OR nodes
                // Must have valid left and right children
                uint8 leftChildIndex = uint8((node >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);
                uint8 rightChildIndex = uint8((node >> RIGHT_CHILD_SHIFT) & RIGHT_CHILD_MASK);

                if (leftChildIndex >= rules.nodeCount || rightChildIndex >= rules.nodeCount) {
                    revert InvalidExpressionTree("AND/OR node child indices out of bounds");
                }
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
        uint256[32] storage packedNodes,
        uint8 nodeIndex,
        ParamRule[16] storage rules,
        bytes calldata data
    )
        internal
        returns (bool)
    {
        // Load the packed node from storage (single SLOAD operation)
        uint256 node = packedNodes[nodeIndex];

        // Extract node type (first 2 bits)
        uint8 nodeType = uint8(node & NODE_TYPE_MASK);

        // Evaluate based on node type
        if (nodeType == NODE_TYPE_RULE) {
            // Extract rule index
            uint8 ruleIndex = uint8((node >> RULE_INDEX_SHIFT) & RULE_INDEX_MASK);
            return rules[ruleIndex].check(data);
        } else if (nodeType == NODE_TYPE_NOT) {
            // Extract child index
            uint8 childIndex = uint8((node >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);
            return !evaluateNode(packedNodes, childIndex, rules, data);
        } else if (nodeType == NODE_TYPE_AND) {
            // Extract left child index
            uint8 leftChildIndex = uint8((node >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);

            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);

            // Short-circuit: if left result is false, the AND result is false
            if (!leftResult) return false;

            // Extract right child index
            uint8 rightChildIndex = uint8((node >> RIGHT_CHILD_SHIFT) & RIGHT_CHILD_MASK);

            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        } else if (nodeType == NODE_TYPE_OR) {
            // Extract left child index
            uint8 leftChildIndex = uint8((node >> LEFT_CHILD_SHIFT) & LEFT_CHILD_MASK);

            // Evaluate left child first
            bool leftResult = evaluateNode(packedNodes, leftChildIndex, rules, data);

            // Short-circuit: if left result is true, the OR result is true
            if (leftResult) return true;

            // Extract right child index
            uint8 rightChildIndex = uint8((node >> RIGHT_CHILD_SHIFT) & RIGHT_CHILD_MASK);

            // Evaluate right child and return result
            return evaluateNode(packedNodes, rightChildIndex, rules, data);
        }

        // Should never reach here if the tree is valid
        return false;
    }

    /*//////////////////////////////////////////////////////////////
                                 CREATE
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Fills the storage config with the provided memory config
     * @dev Copies all elements from memory to storage
     * @param $config The storage configuration to fill
     * @param config The memory configuration to copy from
     */
    function fill(ActionConfig storage $config, ActionConfig memory config) internal {
        $config.valueLimitPerUse = config.valueLimitPerUse;
        $config.paramRules.ruleCount = config.paramRules.ruleCount;
        $config.paramRules.nodeCount = config.paramRules.nodeCount;
        $config.paramRules.rootNodeIndex = config.paramRules.rootNodeIndex;

        // Copy rules
        for (uint8 i; i < config.paramRules.ruleCount; i++) {
            $config.paramRules.rules[i] = config.paramRules.rules[i];
        }

        // Copy packed nodes
        for (uint8 i; i < config.paramRules.nodeCount; i++) {
            $config.paramRules.packedNodes[i] = config.paramRules.packedNodes[i];
        }
    }

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

    /*//////////////////////////////////////////////////////////////
                                  GET
    //////////////////////////////////////////////////////////////*/

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
