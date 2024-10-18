import "../Base.t.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";

import { SmartSessionCompatibilityFallback } from "contracts/SmartSessionCompatibilityFallback.sol";

import { EIP712 } from "solady/utils/EIP712.sol";
import { LibString } from "solady/utils/LibString.sol";
import { MODULE_TYPE_FALLBACK } from "modulekit/external/ERC7579.sol";

import { CALLTYPE_SINGLE } from "modulekit/external/ERC7579.sol";

contract SmartSessionERC1271Test is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    struct _TestTemps {
        address owner;
        uint256 chainId;
        uint256 tokenId;
        bytes32 salt;
        address account;
        address signer;
        uint256 privateKey;
        uint8 v;
        bytes32 r;
        bytes32 s;
    }

    enum ERC1271Result {
        SUCCESS,
        FAIL,
        REVERT
    }

    PermissionId permissionId;
    PermissionId permissionId_invalid;
    SmartSessionCompatibilityFallback fallbackModule;

    function setUp() public virtual override {
        super.setUp();

        fallbackModule = new SmartSessionCompatibilityFallback();

        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_SINGLE, "");
        instance.installModule({ moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner1.addr),
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: new ActionData[](0)
        });

        Session memory session_invalid = Session({
            sessionValidator: ISessionValidator(address(simpleSessionValidator)),
            salt: keccak256("salt_pepper"),
            sessionValidatorInitData: abi.encodePacked(sessionSigner1.addr),
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("Permit(bytes32 stuff)", new PolicyData[](0)),
            actions: new ActionData[](0)
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
        _testIsValidSignature("Permit(bytes32 stuff)", ERC1271Result.SUCCESS, permissionId, hex'00');
    }

    function test_ERC1271_fails_with_0_ERC1271Policies() public {
        console2.log("using permissionId");
        console2.logBytes32(PermissionId.unwrap(permissionId_invalid));
        bytes memory revertReason = abi.encodeWithSelector(
            ISmartSession.NoPoliciesSet.selector,
            permissionId_invalid
        );
        _testIsValidSignature("Permit(bytes32 stuff)", ERC1271Result.REVERT, permissionId_invalid, revertReason); 
    }

    // By right, this should be a proper domain separator, but I'm lazy.
    bytes32 internal constant _DOMAIN_SEP_B = 0xa1a044077d7677adbbfa892ded5390979b33993e0e2a457e3f974bbcda53821b;

    function _testIsValidSignature(bytes memory contentsType, ERC1271Result res, PermissionId _permissionId, bytes memory revertReason) internal {
        bytes32 contents = keccak256(abi.encode("random", contentsType));
        console2.log("contents");
        console2.logBytes32(contents);

        _TestTemps memory t = _testTemps(sessionSigner1);
        // (t.signer, t.privateKey) = _randomSigner();
        (t.v, t.r, t.s) = vm.sign(t.privateKey, _toERC1271Hash(address(t.account), contents, contentsType));

        bytes memory signature =
            abi.encodePacked(t.r, t.s, t.v, _DOMAIN_SEP_B, contents, contentsType, uint16(contentsType.length));
        signature = abi.encodePacked(_permissionId, signature);
        signature = _erc6492Wrap(signature);

        // signature = abi.encodePacked(permissionId, signature);
        // Success returns `0x1626ba7e`.
        if (res == ERC1271Result.REVERT) {
            vm.expectRevert(revertReason);
            IERC1271(t.account).isValidSignature(
                    _toContentsHash(contents), abi.encodePacked(address(smartSession), signature)
                );
        } else {
            bytes4 retValue = IERC1271(t.account).isValidSignature(
                    _toContentsHash(contents), abi.encodePacked(address(smartSession), signature)
                );
            assertEq(
                retValue,
                res == ERC1271Result.SUCCESS ? bytes4(0x1626ba7e) : bytes4(0xffffffff)
            );
        }
    }

    function _erc6492Wrap(bytes memory signature) internal returns (bytes memory) {
        return abi.encodePacked(
            abi.encode(address(1234), "wrap", signature),
            bytes32(0x6492649264926492649264926492649264926492649264926492649264926492)
        );
    }

    function _toERC1271Hash(
        address account,
        bytes32 contents,
        bytes memory contentsType
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHash(contentsType), contents), _accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", _DOMAIN_SEP_B, parentStructHash));
    }

    struct _AccountDomainStruct {
        bytes1 fields;
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
        uint256[] extensions;
    }

    function _accountDomainStructFields(address account) internal view returns (bytes memory) {
        _AccountDomainStruct memory t;
        (t.fields, t.name, t.version, t.chainId, t.verifyingContract, t.salt, t.extensions) =
            EIP712(account).eip712Domain();

        return abi.encode(
            t.fields,
            keccak256(bytes(t.name)),
            keccak256(bytes(t.version)),
            t.chainId,
            t.verifyingContract,
            t.salt,
            keccak256(abi.encodePacked(t.extensions))
        );
    }

    function _typedDataSignTypeHash(bytes memory contentsType) internal pure returns (bytes32) {
        bytes memory ct = contentsType;
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                LibString.slice(string(ct), 0, LibString.indexOf(string(ct), "(", 0)),
                " contents,bytes1 fields,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt,uint256[] extensions)",
                ct
            )
        );
    }

    function _testTemps(Account memory sessionSigner) internal returns (_TestTemps memory t) {
        Account memory signer = sessionSigner;
        t.owner = makeAddr("owner");
        t.signer = signer.addr;
        t.privateKey = signer.key;
        t.tokenId = 1;
        t.chainId = block.chainid;
        t.salt = keccak256(abi.encodePacked("foo"));
        t.account = instance.account;
    }

    function _toContentsHash(bytes32 contents) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", _DOMAIN_SEP_B, contents));
    }
}
