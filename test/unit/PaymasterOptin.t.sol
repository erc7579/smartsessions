import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";

import "contracts/external/policies/ERC20SpendingLimitPolicy.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "forge-std/interfaces/IERC20.sol";
import { MockPaymaster } from "../mock/MockPaymaster.sol";

address constant ENTRYPOINT_ADDR = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

contract PaymasterOptTest is BaseTest {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    MockPaymaster paymaster;

    MockERC20 token;
    PermissionId permissionId;

    function setUp() public virtual override {
        super.setUp();

        paymaster = new MockPaymaster(IEntryPoint(ENTRYPOINT_ADDR));
        token = new MockERC20("MockToken", "MTK", 18);

        paymaster.deposit{ value: 100 ether }();

        token.mint(instance.account, 100 ether);
    }

    function test_transferWithPaymaster() public {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: _getEmptyActionDatas(address(token), IERC20.transfer.selector, address(yesPolicy)),
            permitERC4337Paymaster: true
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        address recipient = makeAddr("recipient");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(1_000_000), uint128(10_000_000));
        userOpData.execUserOps();
        assertEq(token.balanceOf(recipient), 1 ether);
    }

    function test_transferWithPaymaster_paymasterNotEnabled() public {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: _getEmptyActionDatas(address(token), IERC20.transfer.selector, address(yesPolicy)),
            permitERC4337Paymaster: false // cant use paymaster
         });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        address recipient = makeAddr("recipient");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(1_000_000), uint128(10_000_000));
        instance.expect4337Revert();
        userOpData.execUserOps();
    }

    function test_transferWithPaymaster_paymasterEnabledNoPolicy() public {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: _getEmptyActionDatas(address(token), IERC20.transfer.selector, address(yesPolicy)),
            permitERC4337Paymaster: false
        });

        permissionId = smartSession.getPermissionId(session);

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;

        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        address recipient = makeAddr("recipient");

        UserOpData memory userOpData = instance.getExecOps({
            target: address(token),
            value: 0,
            callData: abi.encodeCall(IERC20.transfer, (recipient, 1 ether)),
            txValidator: address(smartSession)
        });
        // session key signs the userOP NOTE: this is using encodeUse() since the session is already enabled
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.paymasterAndData =
            abi.encodePacked(address(paymaster), uint128(1_000_000), uint128(10_000_000));
        instance.expect4337Revert();
        userOpData.execUserOps();
    }
}
