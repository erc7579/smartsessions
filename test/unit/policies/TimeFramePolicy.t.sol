import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/PolicyTestBase.t.sol";

contract TimeFramePolicyTest is PolicyTestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    PermissionId permissionId_timeframedSudo;
    PermissionId permissionId_timeframedAction;
    PermissionId permissionId_timeframed1271;

    function setUp() public virtual override {
        super.setUp();

        bytes memory timeFramePolicyInitData = abi.encodePacked(uint128(block.timestamp + 10 minutes), uint128(block.timestamp));
        permissionId_timeframedSudo = _enableUserOpSession(address(timeFramePolicy), timeFramePolicyInitData, instance, keccak256("salt"));
        permissionId_timeframedAction = _enableActionSession(address(timeFramePolicy), timeFramePolicyInitData, instance, keccak256("salt and pepper"));
        permissionId_timeframed1271 = _enable1271Session(address(timeFramePolicy), timeFramePolicyInitData, instance, keccak256("salt and pepper 2"));
    }

    function test_use_timeframe_policy_fails_not_initialized() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        PermissionId invalidPermissionId = _enableUserOpSession(address(timeFramePolicy), abi.encodePacked(uint256(0)), instance, keccak256("sugar"));
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

    function test_use_timeframe_policy_asUserOp_policy_success() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_timeframedSudo, sig: hex"4141414141" });
        // execute userOp with modulekit
        userOpData.execUserOps();
        assertEq(target.value(), 1337);
    }

    function test_use_timeframe_policy_asUserOp_policy_fail() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_timeframedSudo, sig: hex"4141414141" });
        vm.warp(block.timestamp + 11 minutes);

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOp.selector,
            0,
            "AA22 expired or not due"
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
    }

    //test as 1271 policy
    function test_use_timeframe_policy_as_1271_policy_success() public returns (PermissionId permissionId) {
        _testIsValidSignature("Permit(bytes32 stuff)", true, permissionId_timeframed1271, false, sessionSigner1);
    }
    
    //test as 1271 policy
    function test_use_timeframe_policy_as_1271_policy_fail() public returns (PermissionId permissionId) {
        vm.warp(block.timestamp + 11 minutes);
        _testIsValidSignature("Permit(bytes32 stuff)", false, permissionId_timeframed1271, false, sessionSigner1);
    }

    //test as action policy
    function test_use_timeframe_policy_as_Action_policy_success() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_timeframedAction, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(target.value(), 1337);
    }

    //test as action policy
    function test_use_timeframe_policy_as_Action_policy_fail() public returns (PermissionId permissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_timeframedAction, sig: hex"4141414141" });
        vm.warp(block.timestamp + 11 minutes);
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOp.selector,
            0,
            "AA22 expired or not due"
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
    }
}