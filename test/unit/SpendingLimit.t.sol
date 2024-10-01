import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

import "contracts/external/policies/ERC20SpendingLimitPolicy.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";

contract SpendingLimitTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    ERC20SpendingLimitPolicy spendingLimit;

    MockERC20 token;
    PermissionId permissionId;

    function setUp() public virtual override {
        super.setUp();

        spendingLimit = new ERC20SpendingLimitPolicy();
        token = new MockERC20("MockToken", "MTK", 18);

        token.mint(instance.account, 100 ether);

        address _target = address(token);
        ActionId actionId = _target.toActionId(IERC20.transfer.selector);

        address[] memory spendingLimitTokens = new address[](1);
        uint256[] memory spendingLimitLimits = new uint256[](1);
        spendingLimitTokens[0] = address(token);
        spendingLimitLimits[0] = 3 ether;

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(spendingLimit),
            initData: abi.encode(spendingLimitTokens, spendingLimitLimits)
        });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: _target,
            actionTargetSelector: IERC20.transfer.selector,
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: actionDatas
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function test_transferWithSession() public {
        address recipient = makeAddr("recipient");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.balanceOf(recipient), 1 ether);

        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 2.1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
