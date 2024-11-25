// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../Base.t.sol";
import "contracts/ISmartSession.sol";
import { NoPolicy } from "../mock/NoPolicy.sol";

import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";

contract SmartSessionCallTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    MockERC20 token1;
    MockERC20 token2;
    PermissionId permissionId_smartsession;
    PermissionId permissionId_normalFallback;

    NoPolicy noPolicy;

    function setUp() public virtual override {
        super.setUp();

        token1 = new MockERC20("MockToken1", "MTK1", 18);
        token2 = new MockERC20("MockToken2", "MTK2", 18);

        token1.mint(instance.account, 100 ether);
        token2.mint(instance.account, 100 ether);

        noPolicy = new NoPolicy();

        // Prepare Sudo Permission
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG_PERMITTED_TO_CALL_SMARTSESSION,
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            permit4337Paymaster: true
        });

        permissionId_smartsession = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionPolicies: policyDatas
        });

        session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt2"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: actionDatas,
            permit4337Paymaster: true
        });

        permissionId_normalFallback = smartSession.getPermissionId(session);

        enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);
    }

    function test_call_smartsession() public {
        address recipient = makeAddr("recipient");

        uint256 nonceBefore = smartSession.getNonce(permissionId_smartsession, address(instance.account));

        UserOpData memory userOpData = instance.getExecOps({
            target: address(smartSession),
            value: 0,
            callData: abi.encodeCall(ISmartSession.revokeEnableSignature, (permissionId_smartsession)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_smartsession, sig: hex"4141414141" });
        userOpData.execUserOps();

        userOpData = instance.getExecOps({
            target: address(smartSession),
            value: 0,
            callData: abi.encodeCall(ISmartSession.revokeEnableSignature, (permissionId_smartsession)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_smartsession, sig: hex"4141414141" });
        userOpData.execUserOps();

        uint256 nonceAfter = smartSession.getNonce(permissionId_smartsession, address(instance.account));
        assertEq(nonceAfter, nonceBefore + 2);
    }

    function test_call_smartsession_normalFallback__shouldFail() public {
        address recipient = makeAddr("recipient");

        uint256 nonceBefore = smartSession.getNonce(permissionId_normalFallback, address(instance.account));

        UserOpData memory userOpData = instance.getExecOps({
            target: address(smartSession),
            value: 0,
            callData: abi.encodeCall(ISmartSession.revokeEnableSignature, (permissionId_normalFallback)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_normalFallback, sig: hex"4141414141" });
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
