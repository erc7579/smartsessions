import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

import "contracts/external/policies/ERC20SpendingLimitPolicy.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";

contract ERC20SpendingLimitTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    ERC20SpendingLimitPolicy limit;

    MockERC20 token;
    PermissionId permissionId;

    function setUp() public virtual override {
        super.setUp();

        limit = new ERC20SpendingLimitPolicy();
        token = new MockERC20("MockToken", "MTK", 18);

        token.mint(instance.account, 100 ether);

        address _target = address(token);

        address[] memory limitTokens = new address[](1);
        uint256[] memory limitLimits = new uint256[](1);
        limitTokens[0] = address(token);
        limitLimits[0] = 3 ether;

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(limit), initData: abi.encode(limitTokens, limitLimits) });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
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

    function test_transferAfterApprove() public {
        address spender = makeAddr("spender");
        address recipient = makeAddr("recipient");

        // First approve 1 ether
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender), 1 ether);

        // Then transfer 1.5 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1.5 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.balanceOf(recipient), 1.5 ether);

        // Try to approve 0.6 more - should fail as total would be 3.1 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 0.6 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_approveAfterTransfer() public {
        address recipient = makeAddr("recipient");
        address spender = makeAddr("spender");

        // First transfer 1.5 ether
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1.5 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.balanceOf(recipient), 1.5 ether);

        // Then approve 1 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender), 1 ether);

        // Try to transfer 0.6 more - should fail as total would be 3.1 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 0.6 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_approveTransferAndTransferFrom() public {
        address spender = makeAddr("spender");
        address recipient = makeAddr("recipient");

        // First approve 1 ether to spender
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.allowance(instance.account, spender), 1 ether);

        // Direct transfer of 1 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token.balanceOf(recipient), 1 ether);

        // TransferFrom via spender
        vm.prank(spender);
        token.transferFrom(instance.account, recipient, 0.5 ether);
        assertEq(token.balanceOf(recipient), 1.5 ether);

        // Try to approve 2 more - should fail as we're at limit
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 2 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_mixedOperationsUpToLimit() public {
        address spender1 = makeAddr("spender1");
        address spender2 = makeAddr("spender2");
        address recipient = makeAddr("recipient");

        // Approve 0.5 ether to spender1
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender1, 0.5 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();

        // Transfer 1 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();

        // Increase allowance for spender2 by 0.5 ether
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender2, 0.5 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();

        // Transfer remaining 1 ether - should succeed as we're exactly at limit
        userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
    }
}
