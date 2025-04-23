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
    ParamRule[] internal sampleRules;
    uint256[] internal sampleNodes;

    constructor() {
        // Initialize empty arrays
        delete sampleRules;
        delete sampleNodes;
    }

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
        // Ensure the array is large enough
        while (sampleRules.length <= index) {
            sampleRules.push();
        }

        sampleRules[index].condition = condition;
        sampleRules[index].offset = offset;
        sampleRules[index].isLimited = isLimited;
        sampleRules[index].ref = ref;
        sampleRules[index].usage.limit = limitValue;
        sampleRules[index].usage.used = usedValue;
    }

    function setupNodeAt(uint8 index, uint8 nodeType, uint8 ruleIndex, uint8 leftChild, uint8 rightChild) public {
        // Ensure the array is large enough
        while (sampleNodes.length <= index) {
            sampleNodes.push();
        }

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

    function validateTree(uint8 rootIndex) public view returns (bool) {
        ParamRules memory rules;
        rules.rootNodeIndex = rootIndex;

        // Copy rules and nodes to memory for validation
        rules.rules = new ParamRule[](sampleRules.length);
        for (uint256 i = 0; i < sampleRules.length; i++) {
            rules.rules[i] = sampleRules[i];
        }

        rules.packedNodes = new uint256[](sampleNodes.length);
        for (uint256 i = 0; i < sampleNodes.length; i++) {
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
        returns (uint256 valueLimitPerUse, uint8 rootNodeIndex, uint256 rulesLength, uint256 nodesLength)
    {
        ActionConfig storage storageConfig;
        assembly {
            storageConfig.slot := configSlot
        }

        return (
            storageConfig.valueLimitPerUse,
            storageConfig.paramRules.rootNodeIndex,
            storageConfig.paramRules.rules.length,
            storageConfig.paramRules.packedNodes.length
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
        // Ensure rules array is large enough
        while (config.paramRules.rules.length <= ruleIndex) {
            config.paramRules.rules.push();
        }

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
        helper.validateTree(0); // Node array is empty at this point
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
        helper.validateTree(5); // Root index 5 is beyond node count
    }

    function test_validateExpressionTree_whenInvalidRuleIndex() public {
        // Set up nodes in the helper - rule index 5 with only 2 rules
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 5, 0, 0);
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);
        helper.setupRuleAt(1, ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);

        // When validating a tree with an invalid rule index, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(UniActionTreeLib.InvalidExpressionTree.selector, "Rule index out of bounds")
        );
        helper.validateTree(0);
    }

    function test_validateExpressionTree_whenInvalidNotNodeChild() public {
        // Set up nodes in the helper - NOT node with child index 5 but only 1 node
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_NOT, 0, 5, 0);

        // When validating a tree with an invalid NOT node child, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                UniActionTreeLib.InvalidExpressionTree.selector, "NOT node child index out of bounds"
            )
        );
        helper.validateTree(0);
    }

    function test_validateExpressionTree_whenInvalidAndNodeChildren() public {
        // Set up nodes in the helper - AND node with right child index out of bounds
        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_AND, 0, 1, 5);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);

        // When validating a tree with invalid AND node children, it should revert
        vm.expectRevert(
            abi.encodeWithSelector(
                UniActionTreeLib.InvalidExpressionTree.selector, "AND/OR node child indices out of bounds"
            )
        );
        helper.validateTree(0);
    }

    function test_validateExpressionTree_whenValidTree() public {
        // Set up a valid tree in the helper
        helper.setupRuleAt(0, ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);
        helper.setupRuleAt(1, ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);
        helper.setupRuleAt(2, ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);

        helper.setupNodeAt(0, UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        helper.setupNodeAt(1, UniActionTreeLib.NODE_TYPE_RULE, 1, 0, 0);
        helper.setupNodeAt(2, UniActionTreeLib.NODE_TYPE_OR, 0, 0, 1);
        helper.setupNodeAt(3, UniActionTreeLib.NODE_TYPE_RULE, 2, 0, 0);
        helper.setupNodeAt(4, UniActionTreeLib.NODE_TYPE_AND, 0, 2, 3);

        // When validating a valid tree, it should pass
        bool result = helper.validateTree(4);
        assertTrue(result, "Validation should pass for a valid tree");
    }

    function test_validateExpressionTree_maxLimits() public {
        // Test that we enforce max limits

        // Create more than MAX_RULES rules
        for (uint16 i = 0; i < UniActionTreeLib.MAX_RULES + 10; i++) {
            helper.setupRuleAt(uint8(i), ParamCondition.EQUAL, 0, false, bytes32(0), 0, 0);
        }

        // Create more than MAX_NODES nodes
        for (uint16 i = 0; i < UniActionTreeLib.MAX_NODES + 10; i++) {
            helper.setupNodeAt(uint8(i), UniActionTreeLib.NODE_TYPE_RULE, 0, 0, 0);
        }

        // Should revert due to too many rules and nodes
        vm.expectRevert(
            abi.encodeWithSelector(UniActionTreeLib.InvalidExpressionTree.selector, "Too many rules (max 128)")
        );
        helper.validateTree(0);
    }

    /*//////////////////////////////////////////////////////////////
                                FILL TESTS
    //////////////////////////////////////////////////////////////*/

    function test_fill_copiesAllFields() public {
        // Set up source config with dynamic arrays
        ActionConfig memory sourceConfig;
        sourceConfig.valueLimitPerUse = 123 ether;
        sourceConfig.paramRules.rootNodeIndex = 1;

        // Create rules array
        sourceConfig.paramRules.rules = new ParamRule[](2);

        // Create rule 0
        ParamRule memory rule0;
        rule0.condition = ParamCondition.EQUAL;
        rule0.offset = 0;
        rule0.isLimited = false;
        rule0.ref = bytes32(uint256(VALUE_100));
        sourceConfig.paramRules.rules[0] = rule0;

        // Create rule 1
        ParamRule memory rule1;
        rule1.condition = ParamCondition.GREATER_THAN;
        rule1.offset = 32;
        rule1.isLimited = true;
        rule1.ref = bytes32(uint256(150));
        rule1.usage.limit = 500;
        sourceConfig.paramRules.rules[1] = rule1;

        // Create packed nodes array
        sourceConfig.paramRules.packedNodes = new uint256[](3);
        sourceConfig.paramRules.packedNodes[0] = UniActionTreeLib.createRuleNode(0);
        sourceConfig.paramRules.packedNodes[1] = UniActionTreeLib.createRuleNode(1);
        sourceConfig.paramRules.packedNodes[2] = UniActionTreeLib.createOrNode(0, 1);

        // Fill the config through helper
        helper.fillConfig(testStorageSlot, sourceConfig);

        // Verify all fields were copied correctly
        (uint256 valueLimitPerUse, uint8 rootNodeIndex, uint256 rulesLength, uint256 nodesLength) =
            helper.getConfigValues(testStorageSlot);

        assertEq(valueLimitPerUse, 123 ether, "valueLimitPerUse should be copied");
        assertEq(rootNodeIndex, 1, "rootNodeIndex should be copied");
        assertEq(rulesLength, 2, "rules array length should be correct");
        assertEq(nodesLength, 3, "nodes array length should be correct");

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

    function test_fill_overwritesExistingArrays() public {
        // First create a config with some data
        ActionConfig memory firstConfig;
        firstConfig.valueLimitPerUse = 100 ether;
        firstConfig.paramRules.rootNodeIndex = 0;

        // Create rules array with 3 rules
        firstConfig.paramRules.rules = new ParamRule[](3);
        for (uint8 i = 0; i < 3; i++) {
            ParamRule memory rule;
            rule.condition = ParamCondition.EQUAL;
            rule.offset = i * 32;
            firstConfig.paramRules.rules[i] = rule;
        }

        // Create nodes array with 4 nodes
        firstConfig.paramRules.packedNodes = new uint256[](4);
        for (uint8 i = 0; i < 4; i++) {
            firstConfig.paramRules.packedNodes[i] = UniActionTreeLib.createRuleNode(i % 3);
        }

        // Fill the config
        helper.fillConfig(testStorageSlot, firstConfig);

        // Verify initial state
        (uint256 value1, uint8 root1, uint256 rulesLength1, uint256 nodesLength1) =
            helper.getConfigValues(testStorageSlot);
        assertEq(rulesLength1, 3, "Initial rules length should be 3");
        assertEq(nodesLength1, 4, "Initial nodes length should be 4");

        // Now create a second config with different sized arrays
        ActionConfig memory secondConfig;
        secondConfig.valueLimitPerUse = 200 ether;
        secondConfig.paramRules.rootNodeIndex = 1;

        // Create smaller rules array (2 rules)
        secondConfig.paramRules.rules = new ParamRule[](2);
        for (uint8 i = 0; i < 2; i++) {
            ParamRule memory rule;
            rule.condition = ParamCondition.GREATER_THAN;
            rule.offset = i * 64;
            secondConfig.paramRules.rules[i] = rule;
        }

        // Create larger nodes array (5 nodes)
        secondConfig.paramRules.packedNodes = new uint256[](5);
        for (uint8 i = 0; i < 5; i++) {
            secondConfig.paramRules.packedNodes[i] = UniActionTreeLib.createNotNode(i % 2);
        }

        // Fill the config again (should overwrite the first one)
        helper.fillConfig(testStorageSlot, secondConfig);

        // Verify the new state
        (uint256 value2, uint8 root2, uint256 rulesLength2, uint256 nodesLength2) =
            helper.getConfigValues(testStorageSlot);
        assertEq(value2, 200 ether, "Value should be updated");
        assertEq(root2, 1, "Root index should be updated");
        assertEq(rulesLength2, 2, "Rules length should now be 2");
        assertEq(nodesLength2, 5, "Nodes length should now be 5");

        // Verify rule 0 was updated
        (uint8 condition0,,,,,) = helper.getRule(testStorageSlot, 0);
        assertEq(condition0, uint8(ParamCondition.GREATER_THAN), "Rule 0 condition should be updated");

        // Verify node 0 was updated
        (uint8 nodeType0,,,) = helper.getNode(testStorageSlot, 0);
        assertEq(nodeType0, UniActionTreeLib.NODE_TYPE_NOT, "Node 0 type should be updated");
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
