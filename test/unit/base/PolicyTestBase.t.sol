import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/ERC1271Base.t.sol";
import "contracts/interfaces/IPolicy.sol";

contract PolicyTestBase is ERC1271TestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    address _target;
    uint256 _value;

    function setUp() public virtual override {
        super.setUp();

        _target = address(target);
        _value = 0;
    }

    function _enableUserOpSession(address policy, bytes memory initData, AccountInstance memory instance, bytes32 salt) internal returns (PermissionId permissionId) {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(sudoPolicy), initData: "" });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: FALLBACK_TARGET_FLAG,
            actionTargetSelector: FALLBACK_TARGET_SELECTOR_FLAG,
            actionPolicies: policyDatas
        });

        PolicyData[] memory userOpPolicyDatas = new PolicyData[](1);
        userOpPolicyDatas[0] = PolicyData({ policy: policy, initData: initData });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: userOpPolicyDatas,
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", new PolicyData[](0)),
            actions: actionDatas
        });

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        permissionId = smartSession.getPermissionId(session);
    }

    function _enableActionSession(address policy, bytes memory initData, AccountInstance memory instance, bytes32 salt) internal returns (PermissionId permissionId) {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: policy, initData: initData });

        ActionData[] memory actionDatas = new ActionData[](1);
        actionDatas[0] = ActionData({
            actionTarget: _target,
            actionTargetSelector: target.setValue.selector,
            actionPolicies: policyDatas
        });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", new PolicyData[](0)),
            actions: actionDatas
        });

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        permissionId = smartSession.getPermissionId(session);
    }

    function _enable1271Session(address policy, bytes memory initData, AccountInstance memory instance, bytes32 salt) internal returns (PermissionId permissionId) {
        PolicyData[] memory erc1271PolicyDatas = new PolicyData[](1);
        erc1271PolicyDatas[0] = PolicyData({ policy: policy, initData: initData });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: salt,
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: new PolicyData[](0),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", erc1271PolicyDatas),
            actions: new ActionData[](0)
        });

        Session[] memory enableSessionsArray = new Session[](1);
        enableSessionsArray[0] = session;
        vm.prank(instance.account);
        smartSession.enableSessions(enableSessionsArray);

        permissionId = smartSession.getPermissionId(session);
    }
}