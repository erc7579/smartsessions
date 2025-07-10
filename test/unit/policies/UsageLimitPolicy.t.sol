import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/PolicyTestBase.t.sol";

contract UsageLimitPolicyTest is PolicyTestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    PermissionId permissionId_usageLimitedAction;

    function setUp() public virtual override {
        super.setUp();

        bytes memory usageLimitPolicyInitData = abi.encodePacked(uint128(1));
        permissionId_usageLimitedAction = _enableActionSession(
            address(usageLimitPolicy), usageLimitPolicyInitData, instance, keccak256("salt and pepper")
        );
    }

    function test_usage_limit_policy_init_reinit_use() public {
        PermissionId permissionId = use_usage_limit_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit();
        usage_limit_policy_can_be_reinitialized(permissionId);
    }

    function using_usage_limit_policy_fails_not_initialized() public returns (PermissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        PermissionId invalidPermissionId =
            _enableUserOpSession(address(usageLimitPolicy), abi.encodePacked(uint128(0)), instance, keccak256("salt"));
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

    function use_usage_limit_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit()
        public
        returns (PermissionId)
    {
        //re-initialize
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(usageLimitPolicy), abi.encodePacked(uint128(1)), instance, keccak256("salt"));
        // use
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionIdReInited, sig: hex"4141414141" });
        // execute userOp with modulekit
        userOpData.execUserOps();
        assertEq(target.value(), 1337);

        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        assertEq(usageLimitPolicy.getUsageLimit(configId, address(smartSession), instance.account), uint128(1));
        assertEq(usageLimitPolicy.getUsed(configId, address(smartSession), instance.account), uint128(1));

        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, permissionIdReInited, address(usageLimitPolicy)
        );

        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        return permissionIdReInited;
    }

    function usage_limit_policy_can_be_reinitialized(PermissionId permissionId) public returns (PermissionId) {
        // re-initialize with new limit, check that both limit and used are updated
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(usageLimitPolicy), abi.encodePacked(uint128(2)), instance, keccak256("salt"));
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        assertEq(usageLimitPolicy.getUsageLimit(configId, address(smartSession), instance.account), uint128(2));
        assertEq(usageLimitPolicy.getUsed(configId, address(smartSession), instance.account), uint128(0));
    }

    function test_use_usage_limit_policy_as_action_policy_success_and_fails_if_exceeds_limit()
        public
        returns (PermissionId permissionId)
    {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_usageLimitedAction, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(target.value(), 1337);

        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, permissionId_usageLimitedAction, address(usageLimitPolicy)
        );
        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);

        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }
}
