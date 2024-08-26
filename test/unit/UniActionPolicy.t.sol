import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "contracts/external/policies/UniActionPolicy.sol";

contract UniversalActionPolicyTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    UniActionPolicy internal uniPolicy;
    MockCallee internal mockCallee;

    function setUp() public virtual override {
        super.setUp();
        uniPolicy = new UniActionPolicy();
        mockCallee = new MockCallee();
    }

    function test_use_universal_action_policy(bytes32 salt) public returns (PermissionId permissionId) {
        uint256 valToAdd = 2517;
        bytes32 valToAdd32 = bytes32(uint256(0xdecaf));
        (uint256 prevBal, bytes32 prevBal32) = mockCallee.bals(instance.account);
        assertEq(prevBal, 0);
        assertEq(prevBal32, 0);

        bytes memory callData = abi.encodeCall(MockCallee.addBalance, (instance.account, valToAdd, valToAdd32));
        ActionId actionId = address(mockCallee).toActionId(MockCallee.addBalance.selector);

        PolicyData[] memory actionPolicyDatas = new PolicyData[](1);
        bytes memory uniPolicyInitData = getMockUniPolicyInitData(actionId);
        actionPolicyDatas[0] = PolicyData({ policy: address(uniPolicy), initData: uniPolicyInitData });
        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({ actionId: actionId, actionPolicies: actionPolicyDatas});

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSigner)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(mockCallee),
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();

        (uint256 postBal, bytes32 postBal32) = mockCallee.bals(instance.account);
        assertEq(postBal, valToAdd);
        assertEq(postBal32, valToAdd32);
        assertTrue(uniPolicy.isInitialized(address(smartSession), instance.account));
    }

    function getMockUniPolicyInitData(ActionId actionId) internal view returns (bytes memory policyInitData) {
        ParamRule memory addrRule = ParamRule({
            condition: ParamCondition.EQUAL,
            offset: 0x00,
            isLimited: false,
            ref: bytes32(bytes20(instance.account)) >> 96,
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        ParamRule memory uint256Rule = ParamRule({
            condition: ParamCondition.LESS_THAN,
            offset: 0x20,
            isLimited: true,
            ref: bytes32(uint256(1e30)),
            usage: LimitUsage({ limit: 1e32, used: 0 })
        });
        ParamRule memory bytes32Rule = ParamRule({
            condition: ParamCondition.GREATER_THAN,
            offset: 0x40,
            isLimited: false,
            ref: bytes32(uint256(0x01)),
            usage: LimitUsage({ limit: 0, used: 0 })
        });
        ParamRule[16] memory rules;
        rules[0] = addrRule;
        rules[1] = uint256Rule;
        rules[2] = bytes32Rule;
        ParamRules memory paramRules = ParamRules({ length: 3, rules: rules });
        ActionConfig memory config = ActionConfig({ valueLimitPerUse: 1e21, paramRules: paramRules });
        policyInitData = abi.encode(config);
    }
}

 contract MockCallee {
    struct Balances {
        uint256 uintBalance;
        bytes32 bytes32Balance;
    }

    mapping(address => Balances) public bals;

    function addBalance(address addrParam, uint256 uintParam, bytes32 bytesParam) external {
        bals[addrParam].uintBalance += uintParam;

        bals[addrParam].bytes32Balance = bytes32(uint256(bals[addrParam].bytes32Balance) + uint256(bytesParam));
    }
}
