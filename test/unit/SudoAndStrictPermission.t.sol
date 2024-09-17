// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../Base.t.sol";
import "contracts/ISmartSession.sol";

import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";

contract SudoAndStrictPermissionTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    MockERC20 token1;
    MockERC20 token2;
    PermissionId permissionId_sudo;
    PermissionId permissionId_strict;

    function setUp() public virtual override {
        super.setUp();

        token1 = new MockERC20("MockToken1", "MTK1", 18);
        token2 = new MockERC20("MockToken2", "MTK2", 18);

        token1.mint(instance.account, 100 ether);
        token2.mint(instance.account, 100 ether);


        // Prepare Sudo Permission
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(yesPolicy), initData: "" });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSigner)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: actionDatas
        });

        permissionId_sudo = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);


        // Prepare strict permission
        /* policyDatas[0] = PolicyData({ policy: address(noPolicy), initData: "" });

        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionPolicies: policyDatas
        }); */
            
        session = Session({
            sessionValidator: ISessionValidator(address(yesSigner)),
            salt: keccak256("salt and pepper"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            //actions: actionDatas
            actions: new ActionData[](0) 
        });

        permissionId_strict = smartSession.getPermissionId(session);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function test_transferWithSession_sudo_permission() public {
        address recipient = makeAddr("recipient");

        // Token 1 ok
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token1),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_sudo, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token1.balanceOf(recipient), 1 ether);

        // Token 2 ok
        userOpData = instance.getExecOps({
            target: address(token2),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 100 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_sudo, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(token2.balanceOf(recipient), 100 ether);
    }

    function test_transferWithSession_strict_permission_Fail() public {
        address recipient = makeAddr("recipient");

        // Token 1 fail
        UserOpData memory userOpData = instance.getExecOps({
            target: address(token1),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_strict, sig: hex"4141414141" });
        
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector, 
            0, 
            "AA23 reverted",
            abi.encodeWithSelector(ISmartSession.NoPoliciesSet.selector, permissionId_strict)
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(token1.balanceOf(recipient), 0);

        // Token 2 fail
        userOpData = instance.getExecOps({
            target: address(token2),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 100 ether)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId_strict, sig: hex"4141414141" });
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(token2.balanceOf(recipient), 0);
    }
}
