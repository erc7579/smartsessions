import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/PolicyTestBase.t.sol";

contract ValueLimitPolicyTest is PolicyTestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    PermissionId permissionId_valueLimitedAction;

    bytes valueLimitPolicyInitData;

    function setUp() public virtual override {
        super.setUp();
        valueLimitPolicyInitData = abi.encodePacked(uint256(1e20));
        permissionId_valueLimitedAction = _enableActionSession(
            address(valueLimitPolicy), valueLimitPolicyInitData, instance, keccak256("salt and pepper")
        );
        vm.deal(instance.account, 1e21);
    }

    function test_value_limit_policy_init_reinit_use() public {
        PermissionId permissionId = use_value_limit_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit();
        value_limit_policy_can_be_reinitialized(permissionId);
    }

    function using_value_limit_policy_fails_not_initialized() public returns (PermissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        PermissionId invalidPermissionId =
            _enableUserOpSession(address(valueLimitPolicy), abi.encodePacked(uint256(0)), instance, keccak256("salt"));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: invalidPermissionId, sig: hex"4141414141" });
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodePacked(
                hex"f4270752", // `PolicyCheckReverted(bytes32)`
                IPolicy.PolicyNotInitialized.selector,
                bytes28(
                    ConfigId.unwrap(IdLib.toConfigId(IdLib.toUserOpPolicyId(invalidPermissionId), instance.account))
                )
            )
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
        return invalidPermissionId;
    }

    function use_value_limit_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit()
        public
        returns (PermissionId)
    {
        //re-initialize
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(valueLimitPolicy), valueLimitPolicyInitData, instance, keccak256("salt"));
        // use
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: uint256(1e20 / 2), // half of the limit
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionIdReInited, sig: hex"4141414141" });
        // execute userOp with modulekit
        userOpData.execUserOps();

        // use the other half of the limit with other actionId. should still work as the limit is per session here
        // (userOp Policy)
        callData = abi.encodeCall(MockTarget.increaseValue, ());
        userOpData = instance.getExecOps({
            target: _target,
            value: uint256(1e20 / 2), // half of the limit
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionIdReInited, sig: hex"4141414141" });
        userOpData.execUserOps();

        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        assertEq(valueLimitPolicy.getValueLimit(configId, address(smartSession), instance.account), uint256(1e20));
        assertEq(valueLimitPolicy.getUsed(configId, address(smartSession), instance.account), uint256(1e20));

        // try to exceed the limit, should fail
        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, permissionIdReInited, address(valueLimitPolicy)
        );

        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        return permissionIdReInited;
    }

    function value_limit_policy_can_be_reinitialized(PermissionId permissionId) public returns (PermissionId) {
        // re-initialize with new limit, check that both limit and used are updated
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(valueLimitPolicy), valueLimitPolicyInitData, instance, keccak256("salt"));
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        assertEq(valueLimitPolicy.getValueLimit(configId, address(smartSession), instance.account), uint256(1e20));
        assertEq(valueLimitPolicy.getUsed(configId, address(smartSession), instance.account), 0);
        return permissionIdReInited;
    }

    function value_limit_policy_handle_batch_calls_correctly(PermissionId permissionId) public {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        uint256 batchSize = 3;
        Execution[] memory executions = new Execution[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            executions[i] = Execution({ target: _target, value: uint256(1e10), callData: callData });
        }
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(target.value(), 1337);
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionId), instance.account);
        assertEq(valueLimitPolicy.getUsed(configId, address(smartSession), instance.account), uint256(1e10 * 3));

        // try to exceed the limit, should fail
        Execution[] memory executions2 = new Execution[](batchSize);
        for (uint256 i = 0; i < batchSize; i++) {
            executions2[i] = Execution({ target: _target, value: uint256(1e20 / 2), callData: callData });
        }
        userOpData = instance.getExecOps({ executions: executions2, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        bytes memory innerRevertReason =
            abi.encodeWithSelector(ISmartSession.PolicyViolation.selector, permissionId, address(valueLimitPolicy));
        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_use_value_limit_policy_as_action_policy_success_and_fails_if_exceeds_limit() public {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: uint256(1e20), // full limit
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_valueLimitedAction, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(target.value(), 1337);

        // try to exceed the limit, should fail
        userOpData.userOp.nonce++;
        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, permissionId_valueLimitedAction, address(valueLimitPolicy)
        );
        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);

        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }
}
