import "../Base.t.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";
import { SmartSessionCompatibilityFallback } from "contracts/SmartSessionCompatibilityFallback.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { ERC1271TestBase } from "./base/ERC1271Base.t.sol";

contract SmartSessionERC1271Test is ERC1271TestBase {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    PermissionId permissionId;


    function setUp() public virtual override {
        super.setUp();

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner1.addr),
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: new ActionData[](0)
        });

        Session[] memory sessions = new Session[](1);
        sessions[0] = session;
        vm.prank(instance.account);
        PermissionId[] memory permissions = smartSession.enableSessions(sessions);
        permissionId = permissions[0];
    }

    function test_ERC1271() public {
        console2.log("using permissionId");
        console2.logBytes32(PermissionId.unwrap(permissionId));
        _testIsValidSignature("Permit(bytes32 stuff)", true, permissionId, true, sessionSigner1);
    }
}
