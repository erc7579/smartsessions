import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/ERC1271Base.t.sol";

contract TimeFramePolicyTest is ERC1271TestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    address _target;
    uint256 _value;
    PermissionId permissionId_timeframedSudo;
    PermissionId permissionId_timeframedAction;

    function setUp() public virtual override {
        super.setUp();

        _target = address(target);
        _value = 0;

         // Prepare Timeframed Sudo Permission
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionPolicies: policyDatas
        });

        PolicyData[] memory policyDatasWithTimeFrame = new PolicyData[](1);
        bytes memory timeFramePolicyInitData = abi.encodePacked(uint128(block.timestamp + 10 minutes), uint128(block.timestamp));
        policyDatasWithTimeFrame[0] = PolicyData({ policy: address(timeFramePolicy), initData: timeFramePolicyInitData });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: policyDatasWithTimeFrame,
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", policyDatasWithTimeFrame),
            actions: actionDatas
        });

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        permissionId_timeframedSudo = smartSession.getPermissionId(session);

        // Prepare Timeframed Action Permission
        actionDatas[0] = ActionData({
            actionTarget: _target,
            actionTargetSelector: target.setValue.selector,
            actionPolicies: policyDatasWithTimeFrame
        });

        session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt and pepper"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", new PolicyData[](0)),
            actions: actionDatas
        });

        enableSessionsArray[0] = session;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        permissionId_timeframedAction = smartSession.getPermissionId(session);
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
        _testIsValidSignature("Permit(bytes32 stuff)", true, permissionId_timeframedSudo, false, sessionSigner1);
    }
    
    //test as 1271 policy
    function test_use_timeframe_policy_as_1271_policy_fail() public returns (PermissionId permissionId) {
        vm.warp(block.timestamp + 11 minutes);
        _testIsValidSignature("Permit(bytes32 stuff)", false, permissionId_timeframedSudo, false, sessionSigner1);
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