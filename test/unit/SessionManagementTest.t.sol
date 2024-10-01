import "../Base.t.sol";
import "../mock/MockPolicy.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import {
    ValidationData as ValidationDataStruct,
    _packValidationData,
    _parseValidationData
} from "@ERC4337/account-abstraction/contracts/core/Helpers.sol";

contract SessionManagementTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    MockPolicy policy1;
    MockPolicy policy2;
    MockPolicy policy3;

    function setUp() public virtual override {
        super.setUp();

        policy1 = new MockPolicy();
        vm.label(address(policy1), "policy1");
        policy2 = new MockPolicy();
        vm.label(address(policy2), "policy2");
        policy3 = new MockPolicy();
        vm.label(address(policy3), "policy3");
    }

    function test_enable_exec(bytes32 salt)
        public
        returns (PermissionId permissionId, EnableSession memory enableSessions)
    {
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
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(_target, MockTarget.setValue.selector, address(yesPolicy))
        });

        // predict permissionId correlating to EnableSession
        permissionId = smartSession.getPermissionId(session);

        // get hash for enable signature. A nonce is in here
        uint256 nonceBefore = smartSession.getNonce(permissionId, instance.account);

        // create enable sessions object
        enableSessions = _makeMultiChainEnableData(permissionId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = HashLib.multichainDigest(enableSessions.hashesAndChainIds);

        // user signs the enable hash with wallet
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));

        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeUnsafeEnable(hex"4141414142", enableSessions);

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);

        uint256 nonceAfter = smartSession.getNonce(permissionId, instance.account);
        assertEq(nonceAfter, nonceBefore + 1, "Nonce not updated");

        // now lets re-use the same session to execute another userOp
        userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: abi.encodeCall(MockTarget.setValue, (1338)),
            txValidator: address(smartSession)
        });

        // We can reuse the same permissionId since the session is already enabled
        // NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1338);
    }

    function test_exec(bytes32 salt) public returns (PermissionId permissionId) {
        address _target = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(_target, MockTarget.setValue.selector, address(yesPolicy))
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);
    }

    function test_add_policies_to_permission(bytes32 salt)
        public
        returns (PermissionId permissionId, EnableSession memory enableSessions)
    {
        (permissionId, enableSessions) = test_enable_exec(salt);

        YesPolicy yesPolicy2 = new YesPolicy();

        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1338)),
            txValidator: address(smartSession)
        });

        PolicyData[] memory userOpPolicyData = new PolicyData[](1);
        bytes memory policyInitData = abi.encodePacked(uint256(10));
        userOpPolicyData[0] = PolicyData({ policy: address(usageLimitPolicy), initData: policyInitData });

        // session to add one userOp policy
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: userOpPolicyData,
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: _getEmptyActionDatas(address(target), MockTarget.setValue.selector, address(yesPolicy2))
        });

        enableSessions = _makeMultiChainEnableData(permissionId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = HashLib.multichainDigest(enableSessions.hashesAndChainIds);
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));
        userOpData.userOp.signature = EncodeLib.encodeUnsafeEnable(hex"4141414142", enableSessions);

        userOpData.execUserOps();

        assertEq(target.value(), 1338);
        // assertTrue(usageLimitPolicy.isInitialized(instance.account, address(smartSession), configId));
    }

    function test_disable_permission(bytes32 salt) public {
        (PermissionId permissionId, EnableSession memory enableSessions) = test_add_policies_to_permission(salt);

        vm.prank(instance.account);

        vm.expectEmit(true, true, true, true, address(smartSession));
        emit ISmartSession.SessionRemoved({ permissionId: permissionId, smartAccount: instance.account });
        smartSession.removeSession(permissionId);

        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (4141)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        instance.expect4337Revert();
        userOpData.execUserOps();

        // lets try to replay the same session. THIS MUST FAIL, otherwise session keys can just reenable themselves
        userOpData.userOp.signature = EncodeLib.encodeUnsafeEnable(hex"4141414142", enableSessions);
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
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(_target, MockTarget.setValue.selector, address(yesPolicy))
        });

        // predict permissionId correlating to EnableSession
        PermissionId permissionId = smartSession.getPermissionId(session);

        // get hash for enable signature. A nonce is in here
        uint256 nonceBefore = smartSession.getNonce(permissionId, instance.account);

        // create enable sessions object
        EnableSession memory enableSessions =
            _makeMultiChainEnableData(permissionId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = HashLib.multichainDigest(enableSessions.hashesAndChainIds);

        // user signs the enable hash with wallet
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));

        vm.prank(instance.account);
        smartSession.revokeEnableSignature(permissionId);
        // session key signs the userOP
        userOpData.userOp.signature = EncodeLib.encodeUnsafeEnable(hex"4141414142", enableSessions);

        // execute userOp with modulekit
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_validationData() public {
        address _target = address(target);
        uint256 value = 0;
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));

        ActionData[] memory actionData = new ActionData[](3);
        actionData[0] = _getEmptyActionData(_target, MockTarget.setValue.selector, address(policy1));
        actionData[1] = _getEmptyActionData(_target, MockTarget.setValue.selector, address(policy2));
        actionData[2] = _getEmptyActionData(_target, MockTarget.setValue.selector, address(policy3));

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: bytes32("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: actionData
        });

        PermissionId multiActionPermissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: value,
            callData: callData,
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: multiActionPermissionId, sig: hex"4141414141" });

        uint256 now = block.timestamp;
        policy1.setValidationData(
            _packValidationData({
                sigFailed: false,
                validAfter: uint48(now - 1),
                validUntil: uint48(type(uint48).max - 1)
            })
        );

        policy2.setValidationData(
            _packValidationData({
                sigFailed: false,
                validAfter: uint48(now + 101),
                validUntil: uint48(type(uint48).max - 3)
            })
        );

        policy3.setValidationData(
            _packValidationData({
                sigFailed: false,
                validAfter: uint48(now + 100),
                validUntil: uint48(type(uint48).max - 1)
            })
        );

        vm.prank(instance.account);
        ValidationData ret = smartSession.validateUserOp(userOpData.userOp, keccak256(abi.encode(userOpData.userOp)));
        console2.log("ret", ValidationData.unwrap(ret));

        ValidationDataStruct memory vd = _parseValidationData(ValidationData.unwrap(ret));
        console2.log("vd validAfter:  %s validUntil:  %s", vd.validAfter, vd.validUntil);

        assertEq(vd.validAfter, uint48(now + 101), "after");
        assertEq(vd.validUntil, type(uint48).max - 3, "until");
    }
}
