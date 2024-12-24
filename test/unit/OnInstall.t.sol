import "../Base.t.sol";

contract OnInstallTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    AccountInstance newInstance;

    function setUp() public override {
        super.setUp();

        newInstance = makeAccountInstance("testAccount");

        newInstance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockK1),
            data: abi.encodePacked(owner.addr)
        });
    }

    function test_installModule() public {
        newInstance.installModule({ moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSession), data: "" });

        assertTrue(newInstance.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(smartSession)));
    }

    function test_onInstall() public {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(makeAddr("target"), bytes4(0x41414141), address(yesPolicy)),
            permitERC4337Paymaster: true
        });
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        newInstance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encodePacked(SmartSessionMode.ENABLE, abi.encode(sessions))
        });

        PermissionId permissionId = smartSession.getPermissionId(session);

        assertTrue(newInstance.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(smartSession)));
        assertTrue(smartSession.isInitialized(newInstance.account));
        assertTrue(smartSession.isPermissionEnabled(permissionId, newInstance.account));
    }
}
