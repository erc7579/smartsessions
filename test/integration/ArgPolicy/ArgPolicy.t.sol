// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "contracts/external/policies/ArgPolicy/ArgPolicy.sol";
import "contracts/external/policies/ArgPolicy/lib/ArgPolicyTreeLib.sol";

contract ArgPolicyIntegrationTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;
    using ArgPolicyTreeLib for *;

    ArgPolicy internal uniPolicyV2;
    MockCallee internal mockCallee;

    function setUp() public virtual override {
        super.setUp();
        uniPolicyV2 = new ArgPolicy();
        mockCallee = new MockCallee();
    }

    function test_use_arg_policy_simple_rule_success(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        permissionId = _enableSessionWithArgPolicySimple(salt, instance.account, 1e32, valToAdd32);
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

    function test_use_arg_policy_complex_tree_success(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        permissionId = _enableSessionWithArgPolicyComplex(salt, instance.account, valToAdd, valToAdd32);
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

    function test_use_arg_policy_fails_because_of_limit(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));

        permissionId = _enableSessionWithArgPolicySimple(salt, instance.account, (valToAdd + 1), bytes32(valToAdd32));
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

    function test_use_arg_policy_fails_with_complex_tree(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xaabbcc)); // Different from the expected value in the rule

        permissionId = _enableSessionWithArgPolicyComplex(salt, instance.account, 1e32, bytes32(uint256(0xdecaf)));
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

    function test_use_arg_policy_value_limit_exceeded(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));

        permissionId = _enableSessionWithArgPolicySimple(salt, instance.account, 1e32, bytes32(uint256(0x01)));
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

    function _enableSessionWithArgPolicySimple(
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

    function _enableSessionWithArgPolicyComplex(
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

        // Create dynamic arrays
        ParamRule[] memory rules = new ParamRule[](1);
        rules[0] = bytes32Rule;

        uint256[] memory packedNodes = new uint256[](1);
        packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0);

        // Set up the rules in the ActionConfig
        ActionConfig memory config = ActionConfig({
            valueLimitPerUse: 1e21,
            paramRules: ParamRules({ rootNodeIndex: 0, rules: rules, packedNodes: packedNodes })
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

        // Create dynamic arrays
        ParamRule[] memory rules = new ParamRule[](3);
        rules[0] = addrRule;
        rules[1] = uint256Rule;
        rules[2] = bytes32Rule;

        uint256[] memory packedNodes = new uint256[](5);
        packedNodes[0] = ArgPolicyTreeLib.createRuleNode(0); // Node 0: Address rule
        packedNodes[1] = ArgPolicyTreeLib.createRuleNode(1); // Node 1: Uint256 rule
        packedNodes[2] = ArgPolicyTreeLib.createOrNode(0, 1); // Node 2: OR node (addrRule OR uint256Rule)
        packedNodes[3] = ArgPolicyTreeLib.createRuleNode(2); // Node 3: Bytes32 rule
        packedNodes[4] = ArgPolicyTreeLib.createAndNode(2, 3); // Node 4: AND node (root) - (addrRule OR uint256Rule)
            // AND bytes32Rule

        // Logic: (addrRule OR uint256Rule) AND bytes32Rule
        ActionConfig memory config = ActionConfig({
            valueLimitPerUse: 1e21,
            paramRules: ParamRules({ rootNodeIndex: 4, rules: rules, packedNodes: packedNodes })
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
