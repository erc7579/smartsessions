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
        ActionId actionId,
        bytes32 salt,
        uint256 setValue
    )
        public
        returns (PermissionId permissionId)
    {
        // get userOp from ModuleKit

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSigner)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(actionId, address(yesPolicy))
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
        assertEq(smartSession.isSessionEnabled(permissionId, instance.account), true, "session failed to enable");
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
        ActionId actionId = address(target).toActionId(MockTarget.setValue.selector);
        PermissionId permissionId1 = _makeSession(actionId, "salt1", 1);
        PermissionId permissionId2 = _makeSession(actionId, "salt2", 2);
        PermissionId permissionId3 = _makeSession(actionId, "salt3", 3);
        PermissionId permissionId4 = _makeSession(actionId, "salt4", 4);

        _exec_session(permissionId2, address(target), 0, abi.encodeCall(MockTarget.setValue, (2)));
        assertEq(target.value(), 2);
        _exec_session(permissionId1, address(target), 0, abi.encodeCall(MockTarget.setValue, (1)));
        assertEq(target.value(), 1);
        _exec_session(permissionId3, address(target), 0, abi.encodeCall(MockTarget.setValue, (3)));
        assertEq(target.value(), 3);
        _exec_session(permissionId4, address(target), 0, abi.encodeCall(MockTarget.setValue, (4)));
        assertEq(target.value(), 4);

        // check that the sessions are still enabled
        assertEq(smartSession.isSessionEnabled(permissionId1, instance.account), true, "session 1 should be enabled");
        assertEq(smartSession.isSessionEnabled(permissionId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isSessionEnabled(permissionId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isSessionEnabled(permissionId4, instance.account), true, "session 4 should be enabled");

        // disable session 1
        vm.prank(instance.account);
        smartSession.removeSession(permissionId1);
        assertEq(smartSession.isSessionEnabled(permissionId1, instance.account), false, "session 1 should be disabled");
        assertEq(smartSession.isSessionEnabled(permissionId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isSessionEnabled(permissionId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isSessionEnabled(permissionId4, instance.account), true, "session 4 should be enabled");

        vm.prank(instance.account);
        smartSession.removeSession(permissionId3);
        assertEq(smartSession.isSessionEnabled(permissionId3, instance.account), false, "session 3 should be disabled");
    }
}
