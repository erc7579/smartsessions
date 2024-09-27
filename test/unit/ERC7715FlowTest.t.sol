import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

contract ERC7715FlowTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    UserOperationBuilder internal userOpBuilder;

    function setUp() public virtual override {
        super.setUp();
        address ep = address(instance.aux.entrypoint);
        userOpBuilder = new UserOperationBuilder(ep);
    }

    function test_7715_flow(bytes32 salt)
        public
        returns (PermissionId permissionId, EnableSession memory enableSessions)
    {   
        address _target = address(target);
        uint256 value = 0;
        // bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        ActionId actionId = _target.toActionId(MockTarget.setValue.selector);

        UserOpData memory userOpData =
            instance.getExecOps({ target: address(0), value: 0, callData: "", txValidator: address(0) });

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

        // create enable sessions object
        enableSessions = _makeMultiChainEnableData(permissionId, session, instance, SmartSessionMode.UNSAFE_ENABLE);
        bytes32 hash = HashLib.multichainDigest(enableSessions.hashesAndChainIds);
        enableSessions.permissionEnableSig =
            abi.encodePacked(mockK1, sign(ECDSA.toEthSignedMessageHash(hash), owner.key));

        uint192 nonceKey = uint192(uint160(address(smartSession))) << 32;
        bytes memory context = IntegrationEncodeLib.encodeContext(
            nonceKey, //192 bits, 24 bytes
            ModeLib.encodeSimpleSingle(), //execution mode, 32 bytes
            permissionId,
            enableSessions
        );

        uint256 nonce = userOpBuilder.getNonce(instance.account, context);

        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution(address(target), 0, abi.encodeCall(MockTarget.setValue, (1337)));
        bytes memory callData = userOpBuilder.getCallData(instance.account, executions, context);

        userOpData.userOp.nonce = nonce;
        userOpData.userOp.callData = callData;
        userOpData.userOp.signature = hex"4141414142";

        // format sig
        bytes memory formattedSig = userOpBuilder.formatSignature(instance.account, userOpData.userOp, context);
        userOpData.userOp.signature = formattedSig;

        // execute userOp with modulekit
        userOpData.execUserOps();

        assertEq(target.value(), 1337);

        // TRY AGAIN WITH THE PERMISSION ALREADY ENABLED
        uint256 nonce2 = userOpBuilder.getNonce(instance.account, context);

        executions[0] = Execution(address(target), 0, abi.encodeCall(MockTarget.setValue, (1338)));
        callData = userOpBuilder.getCallData(instance.account, executions, context);

        userOpData.userOp.nonce = nonce2;
        userOpData.userOp.callData = callData;
        userOpData.userOp.signature = hex"4141414142";

        formattedSig = userOpBuilder.formatSignature(instance.account, userOpData.userOp, context);
        userOpData.userOp.signature = formattedSig;

        userOpData.execUserOps();

        assertEq(target.value(), 1338);
    }
}
