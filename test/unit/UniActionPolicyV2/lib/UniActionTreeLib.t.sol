// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../../../Base.t.sol";
import { UniActionTreeLib } from "contracts/external/policies/UniActionPolicyV2/lib/UniActionTreeLib.sol";
import {
    ParamRule,
    ParamRules,
    ActionConfig,
    ParamCondition,
    LimitUsage
} from "contracts/external/policies/UniActionPolicyV2/UniActionPolicyV2.sol";

contract StorageAccessHelper {
    using UniActionTreeLib for *;

    ParamRule internal sampleRule;
    uint256 internal sampleNode;
    ParamRule[16] internal sampleRules;
    uint256[32] internal sampleNodes;

    function setupRule(
        ParamCondition condition,
        uint64 offset,
        bool isLimited,
        bytes32 ref,
        uint256 limitValue,
        uint256 usedValue
    )
        public
    {
        sampleRule.condition = condition;
        sampleRule.offset = offset;
        sampleRule.isLimited = isLimited;
        sampleRule.ref = ref;
        sampleRule.usage.limit = limitValue;
        sampleRule.usage.used = usedValue;
    }

    function checkRule(bytes calldata data) public returns (bool) {
        bool result = sampleRule.check(data);
        return result;
    }

    function getRuleUsed() public view returns (uint256) {
        return sampleRule.usage.used;
    }

    function setupRuleAt(
        uint8 index,
        ParamCondition condition,
        uint64 offset,
        bool isLimited,
        bytes32 ref,
        uint256 limitValue,
        uint256 usedValue
    )
        public
    {
        sampleRules[index].condition = condition;
        sampleRules[index].offset = offset;
        sampleRules[index].isLimited = isLimited;
        sampleRules[index].ref = ref;
        sampleRules[index].usage.limit = limitValue;
        sampleRules[index].usage.used = usedValue;
    }

    function setupNodeAt(uint8 index, uint8 nodeType, uint8 ruleIndex, uint8 leftChild, uint8 rightChild) public {
        if (nodeType == UniActionTreeLib.NODE_TYPE_RULE) {
            sampleNodes[index] = UniActionTreeLib.createRuleNode(ruleIndex);
        } else if (nodeType == UniActionTreeLib.NODE_TYPE_NOT) {
            sampleNodes[index] = UniActionTreeLib.createNotNode(leftChild);
        } else if (nodeType == UniActionTreeLib.NODE_TYPE_AND) {
            sampleNodes[index] = UniActionTreeLib.createAndNode(leftChild, rightChild);
        } else if (nodeType == UniActionTreeLib.NODE_TYPE_OR) {
            sampleNodes[index] = UniActionTreeLib.createOrNode(leftChild, rightChild);
        }
    }

    function evaluateTree(uint8 rootIndex, bytes calldata data) public returns (bool) {
        return UniActionTreeLib.evaluateNode(sampleNodes, rootIndex, sampleRules, data);
    }

    function getRuleUsedAt(uint8 index) public view returns (uint256) {
        return sampleRules[index].usage.used;
    }

    function validateTree(uint8 ruleCount, uint8 nodeCount, uint8 rootIndex) public view returns (bool) {
        ParamRules memory rules;
        rules.ruleCount = ruleCount;
        rules.nodeCount = nodeCount;
        rules.rootNodeIndex = rootIndex;

        // Copy nodes to memory
        for (uint8 i = 0; i < nodeCount; i++) {
            rules.packedNodes[i] = sampleNodes[i];
        }

        // This will revert if invalid
        UniActionTreeLib.validateExpressionTree(rules);
        return true;
    }

    function fillConfig(bytes32 configSlot, ActionConfig memory _config) public {
        ActionConfig storage storageConfig;
        assembly {
            storageConfig.slot := configSlot
        }
        storageConfig.fill(_config);
    }

    function getConfigValues(bytes32 configSlot)
        public
        view
        returns (uint256 valueLimitPerUse, uint8 ruleCount, uint8 nodeCount, uint8 rootNodeIndex)
    {
        ActionConfig storage storageConfig;
        assembly {
            storageConfig.slot := configSlot
        }

        return (
            storageConfig.valueLimitPerUse,
            storageConfig.paramRules.ruleCount,
            storageConfig.paramRules.nodeCount,
            storageConfig.paramRules.rootNodeIndex
        );
    }

    function getRule(
        bytes32 configSlot,
        uint8 ruleIndex
    )
        public
        view
        returns (uint8 condition, uint64 offset, bool isLimited, bytes32 ref, uint256 limit, uint256 used)
    {
        ActionConfig storage storageConfig;
        assembly {
            storageConfig.slot := configSlot
        }

        ParamRule storage rule = storageConfig.paramRules.rules[ruleIndex];
        return (uint8(rule.condition), rule.offset, rule.isLimited, rule.ref, rule.usage.limit, rule.usage.used);
    }

    function getNode(
        bytes32 configSlot,
        uint8 nodeIndex
    )
        public
        view
        returns (uint8 nodeType, uint8 ruleIndex, uint8 leftChild, uint8 rightChild)
    {
        ActionConfig storage storageConfig;
        assembly {
            storageConfig.slot := configSlot
        }

        uint256 node = storageConfig.paramRules.packedNodes[nodeIndex];
        return (
            UniActionTreeLib.getNodeType(node),
            UniActionTreeLib.getRuleIndex(node),
            UniActionTreeLib.getLeftChildIndex(node),
            UniActionTreeLib.getRightChildIndex(node)
        );
    }
}

contract UniActionTreeLibUnitTest is BaseTest {
    /*//////////////////////////////////////////////////////////////
                               LIBRARIES
    //////////////////////////////////////////////////////////////*/

    using UniActionTreeLib for *;

    /*//////////////////////////////////////////////////////////////
                               TEST STORAGE
    //////////////////////////////////////////////////////////////*/

    ActionConfig internal config;
    StorageAccessHelper internal helper;
    bytes32 internal testStorageSlot;

    // Test constants
    uint256 constant VALUE_100 = 100;
    uint256 constant VALUE_200 = 200;
    address constant SAMPLE_ADDRESS = address(0x1234567890123456789012345678901234567890);

    /*//////////////////////////////////////////////////////////////
                                 SETUP
    //////////////////////////////////////////////////////////////*/

    function setUp() public override {
        // Initialize config with default values
        config.valueLimitPerUse = 1 ether;
        config.paramRules.ruleCount = 0;
        config.paramRules.nodeCount = 0;
        config.paramRules.rootNodeIndex = 0;

        // Deploy helper contract
        helper = new StorageAccessHelper();

        // Generate a unique storage slot for testing fill
        testStorageSlot = keccak256(abi.encodePacked("test.storage.slot", block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                             HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Creates test calldata for testing
     */
    function getTestCalldata() internal pure returns (bytes memory) {
        bytes4 selector = bytes4(keccak256("testFunction(uint256,uint256,address)"));
        return abi.encodePacked(selector, abi.encode(VALUE_100, VALUE_200, SAMPLE_ADDRESS));
    }

    /**
     * @notice Creates a sample rule for testing
     * @param ruleIndex The index to store the rule at
     * @param condition The condition to check
     * @param offset The calldata offset for the parameter
     * @param refValue The reference value to compare against
     * @param isLimited Whether the rule has a usage limit
     * @param limitValue The maximum limit if isLimited is true
     */
    function createSampleRule(
        uint8 ruleIndex,
        ParamCondition condition,
        uint64 offset,
        bytes32 refValue,
        bool isLimited,
        uint256 limitValue
    )
        internal
    {
        ParamRule memory rule;
        rule.condition = condition;
        rule.offset = offset;
        rule.isLimited = isLimited;
        rule.ref = refValue;
        if (isLimited) {
            rule.usage.limit = limitValue;
            rule.usage.used = 0;
        }

        config.paramRules.rules[ruleIndex] = rule;
        if (ruleIndex >= config.paramRules.ruleCount) {
            config.paramRules.ruleCount = ruleIndex + 1;
        }
    }

    /*//////////////////////////////////////////////////////////////
                              NODE CREATION
    //////////////////////////////////////////////////////////////*/

    function test_createRuleNode() public {
        // When creating a rule node
        uint8 ruleIndex = 7;
        uint256 node = UniActionTreeLib.createRuleNode(ruleIndex);

        // It should have the correct node type
        assertEq(UniActionTreeLib.getNodeType(node), UniActionTreeLib.NODE_TYPE_RULE, "Node type should be RULE");

        // It should have the correct rule index
        assertEq(UniActionTreeLib.getRuleIndex(node), ruleIndex, "Rule index should match");
    }

    function test_createNotNode() public {
        // When creating a NOT node
        uint8 childIndex = 3;
        uint256 node = UniActionTreeLib.createNotNode(childIndex);

        // It should have the correct node type
        assertEq(UniActionTreeLib.getNodeType(node), UniActionTreeLib.NODE_TYPE_NOT, "Node type should be NOT");

        // It should have the correct child index
        assertEq(UniActionTreeLib.getLeftChildIndex(node), childIndex, "Child index should match");
    }

    function test_createAndNode() public {
        // When creating an AND node
        uint8 leftChildIndex = 1;
        uint8 rightChildIndex = 2;
        uint256 node = UniActionTreeLib.createAndNode(leftChildIndex, rightChildIndex);

        // It should have the correct node type
        assertEq(UniActionTreeLib.getNodeType(node), UniActionTreeLib.NODE_TYPE_AND, "Node type should be AND");

        // It should have the correct child indices
        assertEq(UniActionTreeLib.getLeftChildIndex(node), leftChildIndex, "Left child index should match");
        assertEq(UniActionTreeLib.getRightChildIndex(node), rightChildIndex, "Right child index should match");
    }

    function test_createOrNode() public {
        // When creating an OR node
        uint8 leftChildIndex = 4;
        uint8 rightChildIndex = 5;
        uint256 node = UniActionTreeLib.createOrNode(leftChildIndex, rightChildIndex);

        // It should have the correct node type
        assertEq(UniActionTreeLib.getNodeType(node), UniActionTreeLib.NODE_TYPE_OR, "Node type should be OR");

        // It should have the correct child indices
        assertEq(UniActionTreeLib.getLeftChildIndex(node), leftChildIndex, "Left child index should match");
        assertEq(UniActionTreeLib.getRightChildIndex(node), rightChildIndex, "Right child index should match");
    }

    /*//////////////////////////////////////////////////////////////
                                VALIDATION
    //////////////////////////////////////////////////////////////*/

    function test_validateExpressionTree_whenEmptyTree() public {
        // Set up nodes in the helper
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);

        // When validating an empty tree, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(UniActionTreeLib.InvalidExpressionTree.selector, "Empty expression tree")
        );
        helper.validateTree(1, 0, 0);
    }

    function test_validateExpressionTree_whenInvalidRootIndex() public {
        // Set up nodes in the helper
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_RULE, 2, 0, 0);

        // When validating a tree with an invalid root index, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(UniActionTreeLib.InvalidExpressionTree.selector, "Root node index out of bounds")
        );
        helper.validateTree(3, 3, 5);
    }

    function test_validateExpressionTree_whenInvalidRuleIndex() public {
        // Set up nodes in the helper - rule index 5 with only 2 rules
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 5, 0, 0);

        // When validating a tree with an invalid rule index, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(UniActionTreeLib.InvalidExpressionTree.selector, "Rule index out of bounds")
        );
        helper.validateTree(2, 1, 0);
    }

    function test_validateExpressionTree_whenInvalidNotNodeChild() public {
        // Set up nodes in the helper - NOT node with child index 5 but only 3 nodes
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_NOT, 0, 5, 0);

        // When validating a tree with an invalid NOT node child, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                UniActionTreeLib.InvalidExpressionTree.selector, "NOT node child index out of bounds"
            )
        );
        helper.validateTree(1, 1, 0);
    }

    function test_validateExpressionTree_whenInvalidAndNodeChildren() public {
        // Set up nodes in the helper - AND node with right child index out of bounds
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_AND, 0, 1, 5);

        // When validating a tree with invalid AND node children, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                UniActionTreeLib.InvalidExpressionTree.selector, "AND/OR node child indices out of bounds"
            )
        );
        helper.validateTree(1, 1, 0);
    }

    function test_validateExpressionTree_whenValidTree() public {
        // Set up a valid tree in the helper
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);
        helper.setupNodeAt(3, UniActionTreeLib.NODE_TYPE_RULE, 2, 0, 0);
        helper.setupNodeAt(4, UniActionTreeLib.NODE_TYPE_AND, 0, 2, 3);

        // When validating a valid tree, it should pass
        bool result = helper.validateTree(3, 5, 4);
        assertTrue(result, "Validation should pass for a valid tree");
    }

    /*//////////////////////////////////////////////////////////////
                              RULE EVALUATION
    //////////////////////////////////////////////////////////////*/

    function test_check_whenEqualCondition_passesWhenEqual() public {
        // When checking a rule with EQUAL condition that matches
        helper.setupRule(
            ParamCondition.EQUAL,
            0, // offset for param1
            false,
            bytes32(uint256(VALUE_100)),
            0,
            0
        );

        // It should return true
        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param1 == 100)");
    }

    function test_check_whenEqualCondition_failsWhenNotEqual() public {
        // When checking a rule with EQUAL condition that doesn't match
        helper.setupRule(
            ParamCondition.EQUAL,
            0, // offset for param1
            false,
            bytes32(uint256(101)), // Different value than 100
            0,
            0
        );

        // It should return false
        bool result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param1 != 101)");
    }

    function test_check_whenGreaterThanCondition_passesWhenGreater() public {
        // When checking a rule with GREATER_THAN condition that matches
        helper.setupRule(
            ParamCondition.GREATER_THAN,
            32, // offset for param2
            false,
            bytes32(uint256(150)), // 200 > 150
            0,
            0
        );

        // It should return true
        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 > 150)");
    }

    function test_check_whenGreaterThanCondition_failsWhenEqual() public {
        // When checking a rule with GREATER_THAN condition with equal values
        helper.setupRule(
            ParamCondition.GREATER_THAN,
            32, // offset for param2
            false,
            bytes32(uint256(VALUE_200)), // 200 == 200
            0,
            0
        );

        // It should return false
        bool result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 == 200, not > 200)");
    }

    function test_check_whenGreaterThanCondition_failsWhenSmaller() public {
        // When checking a rule with GREATER_THAN condition with smaller value
        helper.setupRule(
            ParamCondition.GREATER_THAN,
            32, // offset for param2
            false,
            bytes32(uint256(250)), // 200 < 250
            0,
            0
        );

        // It should return false
        bool result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 < 250)");
    }

    function test_check_whenLessThanCondition_passesWhenSmaller() public {
        // When checking a rule with LESS_THAN condition that matches
        helper.setupRule(
            ParamCondition.LESS_THAN,
            32, // offset for param2
            false,
            bytes32(uint256(250)), // 200 < 250
            0,
            0
        );

        // It should return true
        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 < 250)");
    }

    function test_check_whenLessThanCondition_failsWhenEqual() public {
        // When checking a rule with LESS_THAN condition with equal values
        helper.setupRule(
            ParamCondition.LESS_THAN,
            32, // offset for param2
            false,
            bytes32(uint256(VALUE_200)), // 200 == 200
            0,
            0
        );

        // It should return false
        bool result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 == 200, not < 200)");
    }

    function test_check_whenGreaterThanOrEqualCondition() public {
        // Test case 1: when greater
        helper.setupRule(
            ParamCondition.GREATER_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(150)), // 200 > 150
            0,
            0
        );

        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 > 150)");

        // Test case 2: when equal
        helper.setupRule(
            ParamCondition.GREATER_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(VALUE_200)), // 200 == 200
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 == 200)");

        // Test case 3: when smaller
        helper.setupRule(
            ParamCondition.GREATER_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(250)), // 200 < 250
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 < 250)");
    }

    function test_check_whenLessThanOrEqualCondition() public {
        // Test case 1: when smaller
        helper.setupRule(
            ParamCondition.LESS_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(250)), // 200 < 250
            0,
            0
        );

        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 < 250)");

        // Test case 2: when equal
        helper.setupRule(
            ParamCondition.LESS_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(VALUE_200)), // 200 == 200
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 == 200)");

        // Test case 3: when greater
        helper.setupRule(
            ParamCondition.LESS_THAN_OR_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(150)), // 200 > 150
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 > 150)");
    }

    function test_check_whenNotEqualCondition() public {
        // Test case 1: when not equal
        helper.setupRule(
            ParamCondition.NOT_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(150)), // 200 != 150
            0,
            0
        );

        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 != 150)");

        // Test case 2: when equal
        helper.setupRule(
            ParamCondition.NOT_EQUAL,
            32, // offset for param2
            false,
            bytes32(uint256(VALUE_200)), // 200 == 200
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 == 200)");
    }

    function test_check_whenInRangeCondition() public {
        // Test case 1: when in range
        // Pack min and max into a single bytes32 (min: 150, max: 250)
        bytes32 range = bytes32((uint256(150) << 128) | uint256(250));

        helper.setupRule(
            ParamCondition.IN_RANGE,
            32, // offset for param2
            false,
            range, // 150 < 200 < 250
            0,
            0
        );

        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (150 < param2 < 250)");

        // Test case 2: when below range
        range = bytes32((uint256(250) << 128) | uint256(300));

        helper.setupRule(
            ParamCondition.IN_RANGE,
            32, // offset for param2
            false,
            range, // 200 < 250
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 < 250)");

        // Test case 3: when above range
        range = bytes32((uint256(50) << 128) | uint256(150));

        helper.setupRule(
            ParamCondition.IN_RANGE,
            32, // offset for param2
            false,
            range, // 200 > 150
            0,
            0
        );

        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (param2 > 150)");
    }

    function test_check_whenLimitedRule_withinLimit() public {
        // When checking a rule with a limit that is not exceeded
        helper.setupRule(
            ParamCondition.LESS_THAN,
            32, // offset for param2
            true,
            bytes32(uint256(250)), // 200 < 250
            500, // limit
            0 // used
        );

        // It should return true and update the usage
        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Rule should evaluate to true (param2 < 250 and below limit)");

        uint256 used = helper.getRuleUsed();
        assertEq(used, VALUE_200, "Usage should be tracked");
    }

    function test_check_whenLimitedRule_exceedsLimit() public {
        // When checking a rule with a limit that is exceeded
        helper.setupRule(
            ParamCondition.LESS_THAN,
            32, // offset for param2
            true,
            bytes32(uint256(250)), // 200 < 250
            150, // limit (less than 200)
            0 // used
        );

        // It should return false
        bool result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Rule should evaluate to false (limit exceeded)");
    }

    function test_check_whenLimitedRule_multipleUses() public {
        // When checking a rule with a limit over multiple uses
        helper.setupRule(
            ParamCondition.LESS_THAN,
            32, // offset for param2
            true,
            bytes32(uint256(250)), // 200 < 250
            500, // limit
            0 // used
        );

        // First check should succeed
        bool result = helper.checkRule(getTestCalldata());
        assertTrue(result, "First check should succeed");

        uint256 used = helper.getRuleUsed();
        assertEq(used, VALUE_200, "First usage should be tracked");

        // Second check should succeed
        result = helper.checkRule(getTestCalldata());
        assertTrue(result, "Second check should succeed");

        used = helper.getRuleUsed();
        assertEq(used, VALUE_200 * 2, "Second usage should be tracked");

        // Third check should fail
        result = helper.checkRule(getTestCalldata());
        assertFalse(result, "Third check should fail as limit is exceeded");

        used = helper.getRuleUsed();
        assertEq(used, VALUE_200 * 2, "Usage should not increase when limit is exceeded");
    }

    function test_check_batchExecution() public {
        // Set up multiple rules for batch testing
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0);
        helper.setupRuleAt(1, ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0);
        helper.setupRuleAt(2, ParamCondition.GREATER_THAN, 32, false, bytes32(uint256(150)), 0, 0);

        // Transfer rule 0 to sampleRule before checking
        helper.setupRule(ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0);
        bool result0 = helper.checkRule(getTestCalldata());
        assertTrue(result0, "Rule 0 should be true");

        // Rule 1 should be false (param1 != 101)
        helper.setupRule(ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0);
        bool result1 = helper.checkRule(getTestCalldata());
        assertFalse(result1, "Rule 1 should be false");

        // Rule 2 should be true (param2 > 150)
        helper.setupRule(ParamCondition.GREATER_THAN, 32, false, bytes32(uint256(150)), 0, 0);
        bool result2 = helper.checkRule(getTestCalldata());
        assertTrue(result2, "Rule 2 should be true");
    }

    /*//////////////////////////////////////////////////////////////
                             TREE EVALUATION
    //////////////////////////////////////////////////////////////*/

    function test_evaluateExpressionTree_whenSingleRuleNode() public {
        // Setup a single rule node
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0);
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);

        // Evaluate the tree
        bool result = helper.evaluateTree(0, getTestCalldata());
        assertTrue(result, "Single rule node should evaluate to true");
    }

    function test_evaluateExpressionTree_whenNotNode() public {
        // Setup a NOT node with a rule that will evaluate to false
        helper.setupRuleAt(0, ParamCondition.NOT_EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0);
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_NOT, 0, 0, 0);

        // Evaluate the tree
        bool result = helper.evaluateTree(1, getTestCalldata());
        assertTrue(result, "NOT node should negate the child result");
    }

    function test_evaluateExpressionTree_whenAndNode_bothTrue() public {
        // Setup an AND node with two rules that will both evaluate to true
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0);
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(VALUE_200)), 0, 0);

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_AND, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertTrue(result, "AND node should be true when both children are true");
    }

    function test_evaluateExpressionTree_whenAndNode_leftFalse() public {
        // Setup an AND node where the left child evaluates to false
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0); // False
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(VALUE_200)), 0, 0); // True

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_AND, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertFalse(result, "AND node should be false when left child is false");
    }

    function test_evaluateExpressionTree_whenAndNode_rightFalse() public {
        // Setup an AND node where the right child evaluates to false
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(201)), 0, 0); // False

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_AND, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertFalse(result, "AND node should be false when right child is false");
    }

    function test_evaluateExpressionTree_whenOrNode_bothTrue() public {
        // Setup an OR node where both children evaluate to true
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(VALUE_200)), 0, 0); // True

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertTrue(result, "OR node should be true when both children are true");
    }

    function test_evaluateExpressionTree_whenOrNode_leftTrue() public {
        // Setup an OR node where the left child evaluates to true
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(201)), 0, 0); // False

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertTrue(result, "OR node should be true when left child is true");
    }

    function test_evaluateExpressionTree_whenOrNode_rightTrue() public {
        // Setup an OR node where the right child evaluates to true
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0); // False
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(VALUE_200)), 0, 0); // True

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertTrue(result, "OR node should be true when right child is true");
    }

    function test_evaluateExpressionTree_whenOrNode_bothFalse() public {
        // Setup an OR node where both children evaluate to false
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0); // False
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, false, bytes32(uint256(201)), 0, 0); // False

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertFalse(result, "OR node should be false when both children are false");
    }

    function test_evaluateExpressionTree_whenComplexExpression_allConditionsMet() public {
        // Setup a complex expression tree: ((param1 == 100) OR (param2 > 150)) AND ((param3 == SAMPLE_ADDRESS) OR
        // (param2 < 300))

        // Setup rules
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.GREATER_THAN, 32, false, bytes32(uint256(150)), 0, 0); // True
        helper.setupRuleAt(2, ParamCondition.EQUAL, 64, false, bytes32(uint256(uint160(SAMPLE_ADDRESS))), 0, 0); // True
        helper.setupRuleAt(3, ParamCondition.LESS_THAN, 32, false, bytes32(uint256(300)), 0, 0); // True

        // Setup nodes
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);
        helper.setupNodeAt(3, UniActionTreeLib.NODE_TYPE_RULE, 2, 0, 0);
        helper.setupNodeAt(4, UniActionTreeLib.NODE_TYPE_RULE, 3, 0, 0);
        helper.setupNodeAt(5, UniActionTreeLib.NODE_TYPE_OR, 0, 3, 4);
        helper.setupNodeAt(6, UniActionTreeLib.NODE_TYPE_AND, 0, 2, 5);

        // Evaluate the tree
        bool result = helper.evaluateTree(6, getTestCalldata());
        assertTrue(result, "Complex expression should evaluate to true when all conditions are met");
    }

    function test_evaluateExpressionTree_whenComplexExpression_someConditionsNotMet() public {
        // Setup a complex expression tree where some conditions are not met

        // Setup rules - all false except one
        helper.setupRuleAt(0, ParamCondition.NOT_EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // False
        helper.setupRuleAt(1, ParamCondition.LESS_THAN, 32, false, bytes32(uint256(150)), 0, 0); // False
        helper.setupRuleAt(2, ParamCondition.EQUAL, 64, false, bytes32(uint256(uint160(SAMPLE_ADDRESS))), 0, 0); // True
        helper.setupRuleAt(3, ParamCondition.LESS_THAN, 32, false, bytes32(uint256(100)), 0, 0); // False

        // Setup nodes
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);
        helper.setupNodeAt(3, UniActionTreeLib.NODE_TYPE_RULE, 2, 0, 0);
        helper.setupNodeAt(4, UniActionTreeLib.NODE_TYPE_RULE, 3, 0, 0);
        helper.setupNodeAt(5, UniActionTreeLib.NODE_TYPE_OR, 0, 3, 4);
        helper.setupNodeAt(6, UniActionTreeLib.NODE_TYPE_AND, 0, 2, 5);

        // Evaluate the tree
        bool result = helper.evaluateTree(6, getTestCalldata());
        assertFalse(result, "Complex expression should evaluate to false when some conditions are not met");
    }

    function test_evaluateExpressionTree_withShortCircuitEvaluation_orNode() public {
        // Setup an OR node where the left child evaluates to true and the right child has limit tracking
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, true, bytes32(uint256(VALUE_200)), 500, 0); // True with limit

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertTrue(result, "OR node should evaluate to true");

        // Verify the right child was not evaluated (usage should still be 0)
        assertEq(helper.getRuleUsedAt(1), 0, "Right child should not be evaluated due to short-circuit");
    }

    function test_evaluateExpressionTree_withShortCircuitEvaluation_andNode() public {
        // Setup an AND node where the left child evaluates to false and the right child has limit tracking
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(101)), 0, 0); // False
        helper.setupRuleAt(1, ParamCondition.EQUAL, 32, true, bytes32(uint256(VALUE_200)), 500, 0); // True with limit

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_AND, 0, 0, 1);

        // Evaluate the tree
        bool result = helper.evaluateTree(2, getTestCalldata());
        assertFalse(result, "AND node should evaluate to false");

        // Verify the right child was not evaluated (usage should still be 0)
        assertEq(helper.getRuleUsedAt(1), 0, "Right child should not be evaluated due to short-circuit");
    }

    function test_evaluateComplexTree_directNodeAccess() public {
        // Setup rules and nodes for direct node access test
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(uint256(VALUE_100)), 0, 0); // True
        helper.setupRuleAt(1, ParamCondition.GREATER_THAN, 32, false, bytes32(uint256(150)), 0, 0); // True

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);

        // Evaluate specific nodes
        bool result0 = helper.evaluateTree(0, getTestCalldata());
        bool result1 = helper.evaluateTree(1, getTestCalldata());
        bool result2 = helper.evaluateTree(2, getTestCalldata());

        // Check results
        assertTrue(result0, "Node 0 (rule 0) should be true");
        assertTrue(result1, "Node 1 (rule 1) should be true");
        assertTrue(result2, "Node 2 (OR node) should be true");
    }

    /*//////////////////////////////////////////////////////////////
                                FILL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_fill_copiesAllFields() public {
        // Set up source config
        ActionConfig memory sourceConfig;
        sourceConfig.valueLimitPerUse = 123 ether;
        sourceConfig.paramRules.ruleCount = 2;
        sourceConfig.paramRules.nodeCount = 3;
        sourceConfig.paramRules.rootNodeIndex = 1;

        // Create some rules
        ParamRule memory rule0;
        rule0.condition = ParamCondition.EQUAL;
        rule0.offset = 0;
        rule0.isLimited = false;
        rule0.ref = bytes32(uint256(VALUE_100));
        sourceConfig.paramRules.rules[0] = rule0;

        ParamRule memory rule1;
        rule1.condition = ParamCondition.GREATER_THAN;
        rule1.offset = 32;
        rule1.isLimited = true;
        rule1.ref = bytes32(uint256(150));
        rule1.usage.limit = 500;
        sourceConfig.paramRules.rules[1] = rule1;

        // Create some nodes
        sourceConfig.paramRules.packedNodes[0] = UniActionTreeLib.createRuleNode(0);
        sourceConfig.paramRules.packedNodes[1] = UniActionTreeLib.createRuleNode(1);
        sourceConfig.paramRules.packedNodes[2] = UniActionTreeLib.createOrNode(0, 1);

        // Fill the config through helper
        helper.fillConfig(testStorageSlot, sourceConfig);

        // Verify all fields were copied correctly
        (uint256 valueLimitPerUse, uint8 ruleCount, uint8 nodeCount, uint8 rootNodeIndex) =
            helper.getConfigValues(testStorageSlot);

        assertEq(valueLimitPerUse, 123 ether, "valueLimitPerUse should be copied");
        assertEq(ruleCount, 2, "ruleCount should be copied");
        assertEq(nodeCount, 3, "nodeCount should be copied");
        assertEq(rootNodeIndex, 1, "rootNodeIndex should be copied");

        // Verify rule 0
        (uint8 condition0, uint64 offset0, bool isLimited0, bytes32 ref0, uint256 limit0, uint256 used0) =
            helper.getRule(testStorageSlot, 0);

        assertEq(condition0, uint8(ParamCondition.EQUAL), "Rule 0 condition should be copied");
        assertEq(offset0, 0, "Rule 0 offset should be copied");
        assertEq(isLimited0, false, "Rule 0 isLimited should be copied");
        assertEq(ref0, bytes32(uint256(VALUE_100)), "Rule 0 ref should be copied");
        assertEq(limit0, 0, "Rule 0 limit should be copied");
        assertEq(used0, 0, "Rule 0 used should be copied");

        // Verify rule 1
        (uint8 condition1, uint64 offset1, bool isLimited1, bytes32 ref1, uint256 limit1, uint256 used1) =
            helper.getRule(testStorageSlot, 1);

        assertEq(condition1, uint8(ParamCondition.GREATER_THAN), "Rule 1 condition should be copied");
        assertEq(offset1, 32, "Rule 1 offset should be copied");
        assertEq(isLimited1, true, "Rule 1 isLimited should be copied");
        assertEq(ref1, bytes32(uint256(150)), "Rule 1 ref should be copied");
        assertEq(limit1, 500, "Rule 1 limit should be copied");
        assertEq(used1, 0, "Rule 1 used should be copied");

        // Verify node 0
        (uint8 nodeType0, uint8 ruleIndex0, uint8 leftChild0, uint8 rightChild0) = helper.getNode(testStorageSlot, 0);

        assertEq(nodeType0, UniActionTreeLib.NODE_TYPE_RULE, "Node 0 type should be copied");
        assertEq(ruleIndex0, 0, "Node 0 rule index should be copied");

        // Verify node 1
        (uint8 nodeType1, uint8 ruleIndex1, uint8 leftChild1, uint8 rightChild1) = helper.getNode(testStorageSlot, 1);

        assertEq(nodeType1, UniActionTreeLib.NODE_TYPE_RULE, "Node 1 type should be copied");
        assertEq(ruleIndex1, 1, "Node 1 rule index should be copied");

        // Verify node 2
        (uint8 nodeType2, uint8 ruleIndex2, uint8 leftChild2, uint8 rightChild2) = helper.getNode(testStorageSlot, 2);

        assertEq(nodeType2, UniActionTreeLib.NODE_TYPE_OR, "Node 2 type should be copied");
        assertEq(leftChild2, 0, "Node 2 left child should be copied");
        assertEq(rightChild2, 1, "Node 2 right child should be copied");
    }

    /*//////////////////////////////////////////////////////////////
                             GETTER FUNCTIONS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_getterFunctions() public {
        // Create various nodes and test getter functions
        uint8 ruleIndex = 5;
        uint8 leftChild = 2;
        uint8 rightChild = 3;

        uint256 ruleNode = UniActionTreeLib.createRuleNode(ruleIndex);
        uint256 notNode = UniActionTreeLib.createNotNode(leftChild);
        uint256 andNode = UniActionTreeLib.createAndNode(leftChild, rightChild);
        uint256 orNode = UniActionTreeLib.createOrNode(leftChild, rightChild);

        // Test getNodeType
        assertEq(UniActionTreeLib.getNodeType(ruleNode), UniActionTreeLib.NODE_TYPE_RULE, "Should be RULE type");
        assertEq(UniActionTreeLib.getNodeType(notNode), UniActionTreeLib.NODE_TYPE_NOT, "Should be NOT type");
        assertEq(UniActionTreeLib.getNodeType(andNode), UniActionTreeLib.NODE_TYPE_AND, "Should be AND type");
        assertEq(UniActionTreeLib.getNodeType(orNode), UniActionTreeLib.NODE_TYPE_OR, "Should be OR type");

        // Test getRuleIndex
        assertEq(UniActionTreeLib.getRuleIndex(ruleNode), ruleIndex, "Rule index should match");

        // Test getLeftChildIndex
        assertEq(UniActionTreeLib.getLeftChildIndex(notNode), leftChild, "NOT node left child should match");
        assertEq(UniActionTreeLib.getLeftChildIndex(andNode), leftChild, "AND node left child should match");
        assertEq(UniActionTreeLib.getLeftChildIndex(orNode), leftChild, "OR node left child should match");

        // Test getRightChildIndex
        assertEq(UniActionTreeLib.getRightChildIndex(andNode), rightChild, "AND node right child should match");
        assertEq(UniActionTreeLib.getRightChildIndex(orNode), rightChild, "OR node right child should match");
    }
}
