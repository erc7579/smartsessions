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

    PermissionId permissionId_usageLimitedSudo;
    PermissionId permissionId_usageLimitedAction;

    function setUp() public virtual override {
        super.setUp();

        bytes memory usageLimitPolicyInitData = abi.encodePacked(uint128(1));
        permissionId_usageLimitedSudo = _enableUserOpSession(address(usageLimitPolicy), usageLimitPolicyInitData, instance, keccak256("salt"));
        permissionId_usageLimitedAction = _enableActionSession(address(usageLimitPolicy), usageLimitPolicyInitData, instance, keccak256("salt and pepper"));
    }

    function test_use_usage_limit_policy_fails_not_initialized() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        PermissionId invalidPermissionId = _enableUserOpSession(address(usageLimitPolicy), abi.encodePacked(uint128(0)), instance, keccak256("sugar"));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: invalidPermissionId, sig: hex"4141414141" });
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodePacked(
                hex'f4270752', // `PolicyCheckReverted(bytes32)`
                IPolicy.PolicyNotInitialized.selector,
                bytes28(ConfigId.unwrap(IdLib.toConfigId(IdLib.toUserOpPolicyId(invalidPermissionId), instance.account)))
            )
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
    }

    function test_use_usage_limit_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_usageLimitedSudo, sig: hex"4141414141" });
        // execute userOp with modulekit
        userOpData.execUserOps();
        assertEq(target.value(), 1337);

        userOpData.userOp.nonce++;
        
        bytes memory innerRevertReason = abi.encodeWithSelector(
                ISmartSession.PolicyViolation.selector,
                permissionId_usageLimitedSudo,
                address(usageLimitPolicy)
            );

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            innerRevertReason
        );      
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    } 

    function test_use_usage_limit_policy_as_action_policy_success_and_fails_if_exceeds_limit() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_usageLimitedAction, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(target.value(), 1337);

        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
                ISmartSession.PolicyViolation.selector,
                permissionId_usageLimitedAction,
                address(usageLimitPolicy)
            );
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            innerRevertReason);
 
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }
}