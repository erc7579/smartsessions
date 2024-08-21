import "../Base.t.sol";
import "contracts/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";

contract MultipleSessionsTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    event Test__EmitCreatedSessionId(SignerId signerId);

    function setUp() public virtual override {
        super.setUp();
    }

    function _makeSession(bytes32 salt, uint256 setValue) public returns (SignerId signerId) {
        // get userOp from ModuleKit

        Session memory session = Session({
            isigner: ISigner(address(yesSigner)),
            salt: salt,
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy))
        });

        // predict signerId correlating to EnableSessions
        signerId = smartSession.getSignerId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        SignerId[] memory signerIds = smartSession.enableSessions(enableSessionsArray);
        assertEq(SignerId.unwrap(signerId), SignerId.unwrap(signerIds[0]), "signerIds should be the same");
        assertEq(smartSession.isSessionEnabled(signerId, instance.account), true, "session failed to enable");
    }

    function _exec_session(SignerId signerId, address to, uint256 value, bytes memory callData) public {
        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ target: to, value: value, callData: callData, txValidator: address(smartSession) });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: signerId, sig: hex"4141414141" });
        userOpData.execUserOps();
    }

    function test_multiple_session() public {
        SignerId signerId1 = _makeSession("salt1", 1);
        SignerId signerId2 = _makeSession("salt2", 2);
        SignerId signerId3 = _makeSession("salt3", 3);
        SignerId signerId4 = _makeSession("salt4", 4);

        _exec_session(signerId2, address(target), 0, abi.encodeCall(MockTarget.setValue, (2)));
        assertEq(target.value(), 2);
        _exec_session(signerId1, address(target), 0, abi.encodeCall(MockTarget.setValue, (1)));
        assertEq(target.value(), 1);
        _exec_session(signerId3, address(target), 0, abi.encodeCall(MockTarget.setValue, (3)));
        assertEq(target.value(), 3);
        _exec_session(signerId4, address(target), 0, abi.encodeCall(MockTarget.setValue, (4)));
        assertEq(target.value(), 4);

        // check that the sessions are still enabled
        assertEq(smartSession.isSessionEnabled(signerId1, instance.account), true, "session 1 should be enabled");
        assertEq(smartSession.isSessionEnabled(signerId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isSessionEnabled(signerId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isSessionEnabled(signerId4, instance.account), true, "session 4 should be enabled");

        // disable session 1
        vm.prank(instance.account);
        smartSession.removeSession(signerId1);
        assertEq(smartSession.isSessionEnabled(signerId1, instance.account), false, "session 1 should be disabled");
        assertEq(smartSession.isSessionEnabled(signerId2, instance.account), true, "session 2 should be enabled");
        assertEq(smartSession.isSessionEnabled(signerId3, instance.account), true, "session 3 should be enabled");
        assertEq(smartSession.isSessionEnabled(signerId4, instance.account), true, "session 4 should be enabled");

        vm.prank(instance.account);
        smartSession.removeSession(signerId3);
        assertEq(smartSession.isSessionEnabled(signerId3, instance.account), false, "session 3 should be disabled");
    }
}
