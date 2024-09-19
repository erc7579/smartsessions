import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

contract MultipleSessionsTest is BaseTest {
    using ModuleKitHelpers for *;
    using IdLib for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    event Test__EmitCreatedConfigId(PermissionId permissionId);

    function setUp() public virtual override {
        super.setUp();
    }

    function _makeSession(
        address target,
        bytes4 selector,
        bytes32 salt,
        uint256 setValue
    )
        public
        returns (PermissionId permissionId)
    {
        // get userOp from ModuleKit

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(target, selector, address(yesPolicy))
        });

        // predict permissionId correlating to EnableSession
        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        PermissionId[] memory permissionIds = smartSession.enableSessions(enableSessionsArray);
        assertEq(
            PermissionId.unwrap(permissionId), PermissionId.unwrap(permissionIds[0]), "permissionIds should be the same"
        );
        assertEq(smartSession.isPermissionEnabled(permissionId, instance.account), true, "session failed to enable");
    }

    function _exec_session(PermissionId permissionId, address to, uint256 value, bytes memory callData) public {
        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ target: to, value: value, callData: callData, txValidator: address(smartSession) });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
    }

    function test_multiple_session() public {
        address _target = address(target);
        bytes4 selector = MockTarget.setValue.selector;
        PermissionId permissionId1 = _makeSession(_target, selector, "salt1", 1);
        PermissionId permissionId2 = _makeSession(_target, selector, "salt2", 2);
        PermissionId permissionId3 = _makeSession(_target, selector, "salt3", 3);
        PermissionId permissionId4 = _makeSession(_target, selector, "salt4", 4);

        _exec_session(permissionId2, address(target), 0, abi.encodeCall(MockTarget.setValue, (2)));
        assertEq(target.value(), 2);
        _exec_session(permissionId1, address(target), 0, abi.encodeCall(MockTarget.setValue, (1)));
        assertEq(target.value(), 1);
        _exec_session(permissionId3, address(target), 0, abi.encodeCall(MockTarget.setValue, (3)));
        assertEq(target.value(), 3);
        _exec_session(permissionId4, address(target), 0, abi.encodeCall(MockTarget.setValue, (4)));
        assertEq(target.value(), 4);

        // check that the sessions are still enabled
        assertEq(smartSession.isPermissionEnabled(permissionId1, instance.account), true, "session 1 should be enabled");
        assertEq(smartSession.isPermissionEnabled(permissionId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isPermissionEnabled(permissionId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isPermissionEnabled(permissionId4, instance.account), true, "session 4 should be enabled");

        // disable session 1
        vm.prank(instance.account);
        smartSession.removeSession(permissionId1);
        assertEq(
            smartSession.isPermissionEnabled(permissionId1, instance.account), false, "session 1 should be disabled"
        );
        assertEq(smartSession.isPermissionEnabled(permissionId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isPermissionEnabled(permissionId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isPermissionEnabled(permissionId4, instance.account), true, "session 4 should be enabled");

        vm.prank(instance.account);
        smartSession.removeSession(permissionId3);
        assertEq(
            smartSession.isPermissionEnabled(permissionId3, instance.account), false, "session 3 should be disabled"
        );
    }

    function test_batched_exec() public {
        ActionId actionId = address(target).toActionId(MockTarget.setValue.selector);
        PermissionId permissionId = _makeSession(address(target), MockTarget.setValue.selector, "salt1", 1);

        Execution[] memory executions = new Execution[](3);
        executions[0] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (1)) });
        executions[1] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (2)) });
        executions[2] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (3)) });

        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();

        assertEq(target.value(), 3);

        // lets add another actionId to the permission

        ActionId actionId2 = address(target).toActionId(MockTarget.increaseValue.selector);
        ActionData[] memory actionPolicies =
            _getEmptyActionDatas(address(target), MockTarget.increaseValue.selector, address(yesPolicy));

        vm.prank(instance.account);
        smartSession.enableActionPolicies(permissionId, actionPolicies);

        executions = new Execution[](2);
        executions[0] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (1)) });
        executions[1] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.increaseValue, ()) });

        // get userOp from ModuleKit
        userOpData = instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();

        assertEq(target.value(), 2);

        // lets disable the action policy again

        vm.prank(instance.account);
        smartSession.disableActionPolicies(
            permissionId, actionId2, Solarray.addresses(actionPolicies[0].actionPolicies[0].policy)
        );

        userOpData = instance.getExecOps({ executions: executions, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_batched_exec_notAuthorized__shouldFail() public {
        PermissionId permissionId = _makeSession(address(target), MockTarget.setValue.selector, "salt1", 1);

        Execution[] memory executions = new Execution[](3);
        executions[0] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (1)) });
        executions[1] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.increaseValue, ()) });
        executions[2] =
            Execution({ target: address(target), value: 0, callData: abi.encodeCall(MockTarget.setValue, (3)) });

        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_send_value() public {
        address receiver = makeAddr("receiver");
        PermissionId permissionId = _makeSession(receiver, IdLib.VALUE_SELECTOR, "salt1", 1);

        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution({ target: receiver, value: 100, callData: "" });

        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
    }

    function test_payableFunction() public {
        PermissionId permissionId = _makeSession(address(target), MockTarget.setValue.selector, "salt1", 1);

        Execution[] memory executions = new Execution[](1);
        executions[0] =
            Execution({ target: address(target), value: 100, callData: abi.encodeCall(MockTarget.setValue, (1234)) });

        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ executions: executions, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
    }
}
