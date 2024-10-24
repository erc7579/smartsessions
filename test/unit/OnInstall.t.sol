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
            actions: _getEmptyActionDatas(makeAddr("target"), bytes4(0x41414141), address(yesPolicy))
        });
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        newInstance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(smartSession),
            data: abi.encodePacked(SmartSessionMode.ENABLE, abi.encode(sessions))
        });

        assertTrue(newInstance.isModuleInstalled(MODULE_TYPE_VALIDATOR, address(smartSession)));
        assertTrue(smartSession.isInitialized(newInstance.account));
        assertTrue(
            smartSession.isPermissionEnabled(
                PermissionId.wrap(0x0d74975fdf356bd4556eb87e2599a8fce1f6dc2ec902fc5790451d6f2ee0c637),
                newInstance.account
            )
        );
    }
}
