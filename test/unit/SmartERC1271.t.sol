import "../Base.t.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";
import { SmartSessionCompatibilityFallback } from "contracts/SmartSessionCompatibilityFallback.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { ERC1271TestBase } from "./base/ERC1271Base.t.sol";

import { MODULE_TYPE_FALLBACK } from "modulekit/external/ERC7579.sol";
import { CALLTYPE_SINGLE, CALLTYPE_STATIC } from "modulekit/external/ERC7579.sol";
import { AccountType } from "modulekit/test/RhinestoneModuleKit.sol";

contract SmartSessionERC1271Test is ERC1271TestBase {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using HashLib for *;

    PermissionId permissionId;
    PermissionId permissionId_invalid;

    function setUp() public virtual override {
        super.setUp();

        EIP712Domain memory domain = EIP712Domain({
            name: "Forge",
            version: "1",
            chainId: 1,
            verifyingContract: address(0x6605F8785E09a245DD558e55F9A0f4A508434503)
        });
        appDomainSeparator = hash(domain);
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner1.addr),
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)Permit", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: new ActionData[](0),
            permitERC4337Paymaster: true
        });

        Session memory session_invalid = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt_pepper"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner1.addr),
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", new PolicyData[](0)),
            actions: new ActionData[](0),
            permitERC4337Paymaster: true
        });

        Session[] memory sessions = new Session[](2);
        sessions[0] = session;
        sessions[1] = session_invalid;
        vm.prank(instance.account);
        PermissionId[] memory permissions = smartSession.enableSessions(sessions);
        permissionId = permissions[0];
        permissionId_invalid = permissions[1];
    }

    function test_ERC1271() public {
        console2.log("using permissionId");
        console2.logBytes32(PermissionId.unwrap(permissionId));

        _testIsValidSignature({
            contentsType: "Permit(bytes32 stuff)",
            contentsName: "Permit",
            expectSuccess: true,
            permissionId: permissionId,
            is6492: true,
            sessionSigner: sessionSigner1
        });
    }
}
