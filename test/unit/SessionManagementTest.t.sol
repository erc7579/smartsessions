import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";

contract SessionManagementTest is BaseTest {
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

        // get hash for enable signature. A nonce is in here
        uint256 nonceBefore = smartSession.getNonce(signerId, instance.account);

        // create enable sessions object
        enableSessions = _makeMultiChainEnableData(signerId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = keccak256(enableSessions.hashesAndChainIds);

        // user signs the enable hash with wallet
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));

        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeEnable(signerId, hex"4141414142", enableSessions);

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);

        uint256 nonceAfter = smartSession.getNonce(signerId, instance.account);
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
        Session memory session = Session({
            isigner: ISigner(address(yesSigner)),
            salt: salt,
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy))
        });

        signerId = smartSession.getSignerId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

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
        emit ISmartSession.SessionRemoved({ signerId: signerId, smartAccount: instance.account });
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

    function test_revoke_signed_enable(bytes32 salt) public {
        address _target = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));

        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: callData,
            txValidator: address(smartSession)
        });

        Session memory session = Session({
            isigner: ISigner(address(yesSigner)),
            salt: salt,
            isignerInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(ActionId.wrap(bytes32(uint256(1))), address(yesPolicy))
        });

        // predict signerId correlating to EnableSessions
        SignerId signerId = smartSession.getSignerId(session);

        // get hash for enable signature. A nonce is in here
        uint256 nonceBefore = smartSession.getNonce(signerId, instance.account);

        // create enable sessions object
        EnableSessions memory enableSessions =
            _makeMultiChainEnableData(signerId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = keccak256(enableSessions.hashesAndChainIds);

        // user signs the enable hash with wallet
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));

        vm.prank(instance.account);
        smartSession.revokeEnableSignature(signerId);
        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeEnable(signerId, hex"4141414142", enableSessions);

        // execute userOp with modulekit
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
