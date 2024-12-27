// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "contracts/external/policies/ERC20SpendingLimitPolicy.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";

contract SudoPolicyAndActionPolicyTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    MockERC20 token1;
    MockERC20 token2;
    MockERC20 token3;
    PermissionId permissionId;
    PermissionId permissionId_onlyUserOpPolicy;
    ERC20SpendingLimitPolicy spendingLimit;

    function setUp() public virtual override {
        super.setUp();

        token1 = new MockERC20("MockToken1", "MTK1", 18);
        token2 = new MockERC20("MockToken2", "MTK2", 18);
        token3 = new MockERC20("MockToken3", "MTK3", 18);

        token1.mint(instance.account, 100 ether);
        token2.mint(instance.account, 100 ether);
        token3.mint(instance.account, 100 ether);

        spendingLimit = new ERC20SpendingLimitPolicy();

        // Set up spending limit policy for both tokens
        address[] memory spendingLimitTokens = new address[](2);
        uint256[] memory spendingLimitLimits = new uint256[](2);
        spendingLimitTokens[0] = address(token1);
        spendingLimitTokens[1] = address(token2);
        spendingLimitLimits[0] = 3 ether;
        spendingLimitLimits[1] = 3 ether;

        // Create action data for transfer with spending limit policy (token1 only)
        PolicyData[] memory transferPolicyDatas = new PolicyData[](1);
        transferPolicyDatas[0] = PolicyData({
            policy: address(spendingLimit),
            initData: abi.encode(spendingLimitTokens, spendingLimitLimits)
        });

        ActionData[] memory actionDatas = new ActionData[](3);
        actionDatas[0] = ActionData({
            actionTarget: address(token1),
            actionTargetSelector: IERC20.transfer.selector,
            actionPolicies: transferPolicyDatas
        });

        // Add token2 actions with same spending limit policy
        actionDatas[1] = ActionData({
            actionTarget: address(token2),
            actionTargetSelector: IERC20.transfer.selector,
            actionPolicies: transferPolicyDatas
        });

        actionDatas[2] = ActionData({
            actionTarget: address(token2),
            actionTargetSelector: IERC20.approve.selector,
            actionPolicies: transferPolicyDatas
        });

        // Set up sudo policy as UserOp policy
        PolicyData[] memory userOpPolicies = new PolicyData[](1);
        userOpPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: userOpPolicies,
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            permitERC4337Paymaster: true
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        // Create a session with only UserOp policy and no action data
        PolicyData[] memory onlyUserOpPolicies = new PolicyData[](1);
        onlyUserOpPolicies[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        Session memory userOpOnlySession = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt2"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: onlyUserOpPolicies,
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: new ActionData[](0), // Empty action data array
            permitERC4337Paymaster: true
        });

        permissionId_onlyUserOpPolicy = smartSession.getPermissionId(userOpOnlySession);

        enableSessionsArray[0] = userOpOnlySession;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function test_token1_transferWithSpendingLimit() public {
        address recipient = makeAddr("recipient");

        // Should succeed as it's within spending limit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token1),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 2 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token1.balanceOf(recipient), 2 ether);

        // Should fail as it exceeds spending limit
        userOpData = instance.getExecOps({
            target: address(token1),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 4 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_token2_transferWithSpendingLimit() public {
        address recipient = makeAddr("recipient");

        // Should fail as it exceeds spending limit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token2),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 50 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_token3_transferWithNoActionData() public {
        address recipient = makeAddr("recipient");

        // Should revert with NoPoliciesSet since token3 has no action data
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token3),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.NoPoliciesSet.selector, permissionId)
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_token2_approveWithSpendingLimit() public {
        address spender = makeAddr("spender");

        // Should fail as it exceeds spending limit
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token2),
            value: 0,
            callData: abi.encodeCall(IERC20.approve, (spender, 50 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_token1_transferWithOnlyUserOpPolicy() public {
        address recipient = makeAddr("recipient");

        // Should fail as the policy only has a UserOp policy and no action data
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token1),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_onlyUserOpPolicy, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.NoPoliciesSet.selector, permissionId_onlyUserOpPolicy)
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_token2_transferWithOnlyUserOpPolicy() public {
        address recipient = makeAddr("recipient");

        // Should fail as the policy only has a UserOp policy and no action data
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token2),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_onlyUserOpPolicy, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.NoPoliciesSet.selector, permissionId_onlyUserOpPolicy)
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }
}
