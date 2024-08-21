import "../Base.t.sol";
import "contracts/SmartSessionBase.sol";

contract EnableSessionViaUserOpTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for SignerId;

    function setUp() public virtual override {
        super.setUp();
    }

    function test_enable_exec(bytes32 salt) public returns (SignerId signerId, EnableSessions memory enableSessions) {
        // get userOp from ModuleKit

        address _target = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));

        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: callData,
            txValidator: address(smartSession)
        });

        enableSessions = EnableSessions({
            isigner: ISigner(address(yesSigner)),
            salt: salt,
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy)),
            permissionEnableSig: ""
        });

        // predict signerId correlating to EnableSessions
        signerId = smartSession.getSignerId(enableSessions.isigner, enableSessions.salt, enableSessions.isignerInitData);

        // get hash for enable signature. A nonce is in here
        uint256 nonceBefore = smartSession.getNonce(enableSessions.isigner, instance.account);
        bytes32 hash = smartSession.getDigest(
            enableSessions.isigner, instance.account, enableSessions, SmartSessionMode.UNSAFE_ENABLE
        );

        // user signs the enable hash with wallet
        enableSessions.permissionEnableSig = abi.encodePacked(instance.defaultValidator, sign(hash, 1));

        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeEnable(signerId, hex"4141414142", enableSessions);

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);

        uint256 nonceAfter = smartSession.getNonce(enableSessions.isigner, instance.account);
        assertEq(nonceAfter, nonceBefore + 1, "Nonce not updated");

        // now lets re-use the same session to execute another userOp
        userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: abi.encodeCall(MockTarget.setValue, (1338)),
            txValidator: address(smartSession)
        });

        // We can reuse the same signerId since the session is already enabled
        // NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: signerId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1338);
    }

    function test_exec(bytes32 salt) public returns (SignerId signerId) {
        EnableSessions memory enableSessions = EnableSessions({
            isigner: ISigner(address(yesSigner)),
            salt: salt,
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy)),
            permissionEnableSig: ""
        });

        signerId = smartSession.getSignerId(enableSessions.isigner, enableSessions.salt, enableSessions.isignerInitData);

        EnableSessions[] memory enableSessionsArray = new EnableSessions[](1);
        enableSessionsArray[0] = enableSessions;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        address _target = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: signerId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);
    }

    function test_disableSession(bytes32 salt) public {
        (SignerId signerId, EnableSessions memory enableSessions) = test_enable_exec(salt);

        vm.prank(instance.account);

        vm.expectEmit(true, true, true, true, address(smartSession));
        emit SmartSessionBase.SessionRemoved({ signerId: signerId, smartAccount: instance.account });
        smartSession.removeSession(signerId);

        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (4141)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ signerId: signerId, sig: hex"4141414141" });

        instance.expect4337Revert();
        userOpData.execUserOps();

        // lets try to replay the same session. THIS MUST FAIL, otherwise session keys can just reenable themselves
        userOpData.userOp.signature = EncodeLib.encodeEnable(signerId, hex"4141414142", enableSessions);
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
