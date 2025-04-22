// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "contracts/external/policies/UniActionPolicyV2/UniActionPolicyV2.sol";
import "contracts/external/policies/UniActionPolicyV2/lib/UniActionTreeLib.sol";

contract UniActionPolicyV2IntegrationTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;
    using UniActionTreeLib for *;

    UniActionPolicyV2 internal uniPolicyV2;
    MockCallee internal mockCallee;

    function setUp() public virtual override {
        super.setUp();
        uniPolicyV2 = new UniActionPolicyV2();
        mockCallee = new MockCallee();
    }

    function test_use_universal_action_policy_v2_simple_rule_success(bytes32 salt)
        public
        returns (PermissionId permissionId)
    {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        permissionId = _enableSessionWithUniActionPolicyV2Simple(salt, instance.account, 1e32, valToAdd32);
        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        (uint256 postBal, bytes32 postBal32) = mockCallee.bals(instance.account);
        assertEq(postBal, valToAdd);
        assertEq(postBal32, valToAdd32);
    }

    function test_use_universal_action_policy_v2_complex_tree_success(bytes32 salt)
        public
        returns (PermissionId permissionId)
    {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        permissionId = _enableSessionWithUniActionPolicyV2Complex(salt, instance.account, valToAdd, valToAdd32);
        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        (uint256 postBal, bytes32 postBal32) = mockCallee.bals(instance.account);
        assertEq(postBal, valToAdd);
        assertEq(postBal32, valToAdd32);
    }

    function test_use_universal_action_policy_v2_fails_because_of_limit(bytes32 salt)
        public
        returns (PermissionId permissionId)
    {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));

        permissionId =
            _enableSessionWithUniActionPolicyV2Simple(salt, instance.account, (valToAdd + 1), bytes32(valToAdd32));
        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // first one should pass
        userOpData.execUserOps();

        // create another userOp
        userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.PolicyViolation.selector, permissionId, address(uniPolicyV2))
        );

        // this should revert as the limit has been reached
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_use_universal_action_policy_v2_fails_with_complex_tree(bytes32 salt)
        public
        returns (PermissionId permissionId)
    {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xaabbcc)); // Different from the expected value in the rule

        permissionId =
            _enableSessionWithUniActionPolicyV2Complex(salt, instance.account, 1e32, bytes32(uint256(0xdecaf)));
        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.PolicyViolation.selector, permissionId, address(uniPolicyV2))
        );

        // Should fail because the complex tree condition fails
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_use_universal_action_policy_v2_value_limit_exceeded(bytes32 salt)
        public
        returns (PermissionId permissionId)
    {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));

        permissionId = _enableSessionWithUniActionPolicyV2Simple(salt, instance.account, 1e32, bytes32(uint256(0x01)));
        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));

        // get userOp from ModuleKit with value exceeding the limit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 1e22, // Value exceeds the 1e21 limit set in the policy
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // Should fail because the value limit is exceeded
        vm.expectRevert();
        userOpData.execUserOps();
    }

    /*//////////////////////////////////////////////////////////////
                         HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _enableSessionWithUniActionPolicyV2Simple(
        bytes32 salt,
        address refAddressRef,
        uint256 refUint256,
        bytes32 refBytes32
    )
        internal
        returns (PermissionId permissionId)
    {
        ActionId actionId = address(mockCallee).toActionId(MockCallee.addBalance.selector);

        PolicyData[] memory actionPolicyDatas = new PolicyData[](1);
        bytes memory uniPolicyInitData = _getSimpleUniPolicyV2InitData(actionId, refAddressRef, refUint256, refBytes32);
        actionPolicyDatas[0] = PolicyData({ policy: address(uniPolicyV2), initData: uniPolicyInitData });
        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: address(mockCallee),
            actionTargetSelector: MockCallee.addBalance.selector,
            actionPolicies: actionPolicyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            permitERC4337Paymaster: true
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function _enableSessionWithUniActionPolicyV2Complex(
        bytes32 salt,
        address refAddressRef,
        uint256 refUint256,
        bytes32 refBytes32
    )
        internal
        returns (PermissionId permissionId)
    {
        ActionId actionId = address(mockCallee).toActionId(MockCallee.addBalance.selector);

        PolicyData[] memory actionPolicyDatas = new PolicyData[](1);
        bytes memory uniPolicyInitData = _getComplexUniPolicyV2InitData(actionId, refAddressRef, refUint256, refBytes32);
        actionPolicyDatas[0] = PolicyData({ policy: address(uniPolicyV2), initData: uniPolicyInitData });
        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: address(mockCallee),
            actionTargetSelector: MockCallee.addBalance.selector,
            actionPolicies: actionPolicyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            permitERC4337Paymaster: true
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function _getSimpleUniPolicyV2InitData(
        ActionId actionId,
        address refAddressRef,
        uint256 refUint256,
        bytes32 refBytes32
    )
        internal
        pure
        returns (bytes memory policyInitData)
    {
        // Create simple rule
        ParamRule memory bytes32Rule = ParamRule({
            condition: ParamCondition.GREATER_THAN,
            offset: 0x40,
            isLimited: true,
            ref: bytes32(uint256(refBytes32) - 1),
            usage: LimitUsage({ limit: uint256(refBytes32) + 1, used: 0 })
        });

        // Set up the rules in the ActionConfig
        ActionConfig memory config = ActionConfig({
            valueLimitPerUse: 1e21,
            paramRules: ParamRules({
                ruleCount: 1,
                nodeCount: 1,
                rootNodeIndex: 0,
                rules: [
                    bytes32Rule,
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0))
                ],
                packedNodes: [
                    UniActionTreeLib.createRuleNode(0), // Node 2: Bytes32 rule (root)
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0)
                ]
            })
        });

        policyInitData = abi.encode(config);
    }

    function _getComplexUniPolicyV2InitData(
        ActionId actionId,
        address refAddressRef,
        uint256 refUint256,
        bytes32 refBytes32
    )
        internal
        pure
        returns (bytes memory policyInitData)
    {
        // Create rules
        ParamRule memory addrRule = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0x00,
            isLimited: false,
            ref: bytes32(bytes20(refAddressRef)) >> 96,
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        ParamRule memory uint256Rule = ParamRule({
            condition: ParamCondition.LESS_THAN,
            offset: 0x20,
            isLimited: true,
            ref: bytes32(refUint256),
            usage: LimitUsage({ limit: refUint256, used: 0 })
        });
        ParamRule memory bytes32Rule = ParamRule({
            condition: ParamCondition.EQUAL, // Must be exactly this value
            offset: 0x40,
            isLimited: false,
            ref: refBytes32,
            usage: LimitUsage({ limit: 0, used: 0 })
        });

        // Set up the rules in the ActionConfig with a complex expression tree
        // Logic: (addrRule OR uint256Rule) AND bytes32Rule
        ActionConfig memory config = ActionConfig({
            valueLimitPerUse: 1e21,
            paramRules: ParamRules({
                ruleCount: 3,
                nodeCount: 5,
                rootNodeIndex: 4,
                rules: [
                    addrRule,
                    uint256Rule,
                    bytes32Rule,
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0)),
                    ParamRule(ParamCondition.EQUAL, 0, false, bytes32(0), LimitUsage(0, 0))
                ],
                packedNodes: [
                    UniActionTreeLib.createRuleNode(0), // Node 0: Address rule
                    UniActionTreeLib.createRuleNode(1), // Node 1: Uint256 rule
                    UniActionTreeLib.createOrNode(0, 1), // Node 2: OR node (addrRule OR uint256Rule)
                    UniActionTreeLib.createRuleNode(2), // Node 3: Bytes32 rule
                    UniActionTreeLib.createAndNode(2, 3), // Node 4: AND node (root) - (addrRule OR uint256Rule) AND bytes32Rule
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0),
                    uint256(0)
                ]
            })
        });

        policyInitData = abi.encode(config);
    }
}

contract MockCallee {
    struct Balances {
        uint256 uintBalance;
        bytes32 bytes32Balance;
    }

    mapping(address => Balances) public bals;

    function addBalance(address addrParam, uint256 uintParam, bytes32 bytesParam) external {
        bals[addrParam].uintBalance += uintParam;
        bals[addrParam].bytes32Balance = bytes32(uint256(bals[addrParam].bytes32Balance) + uint256(bytesParam));
    }
}
