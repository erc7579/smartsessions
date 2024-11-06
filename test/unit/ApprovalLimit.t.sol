import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

import "contracts/external/policies/ERC20ApprovalLimitPolicy.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";
import { console2 as console } from "forge-std/console2.sol";

contract ApprovalLimitTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    ERC20ApprovalLimitPolicy approvalLimit;

    MockERC20 token;
    PermissionId permissionId;

    function setUp() public virtual override {
        super.setUp();

        approvalLimit = new ERC20ApprovalLimitPolicy();
        token = new MockERC20("MockToken", "MTK", 18);

        token.mint(instance.account, 100 ether);

        address _target = address(token);

        address[] memory approvalLimitTokens = new address[](1);
        uint256[] memory approvalLimitLimits = new uint256[](1);
        approvalLimitTokens[0] = address(token);
        approvalLimitLimits[0] = 3 ether;

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({
            policy: address(approvalLimit),
            initData: abi.encode(approvalLimitTokens, approvalLimitLimits)
        });

        ActionData[] memory actionDatas = new ActionData[](2);
        actionDatas[0] = ActionData({
            actionTarget: _target,
            actionTargetSelector: IERC20.approve.selector,
            actionPolicies: policyDatas
        });
        actionDatas[1] = ActionData({
            actionTarget: _target,
            actionTargetSelector: bytes4(keccak256("increaseAllowance(address,uint256)")),
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

    function test_approveWithSession() public {
        address spender = makeAddr("spender");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender), 1 ether);

        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 2.1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_multipleApprovalsWithinLimit() public {
        address spender1 = makeAddr("spender1");
        address spender2 = makeAddr("spender2");

        // First approval of 1 ether
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender1, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender1), 1 ether);

        // Second approval of 1.5 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender2, 1.5 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender2), 1.5 ether);

        // Third approval should fail as it exceeds the 3 ether limit
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender1, 0.6 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
