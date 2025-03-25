import "../Base.t.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";

import { SmartSessionCompatibilityFallback } from "contracts/SmartSessionCompatibilityFallback.sol";

import { EIP712 } from "solady/utils/EIP712.sol";
import { LibString } from "solady/utils/LibString.sol";
import { MODULE_TYPE_FALLBACK } from "modulekit/external/ERC7579.sol";

import { CALLTYPE_STATIC } from "modulekit/external/ERC7579.sol";

contract SmartSessionERC1271Test is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using HashLib for *;

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
    bytes32 appDomainSeparator;

    function setUp() public virtual override {
        super.setUp();

        fallbackModule = new SmartSessionCompatibilityFallback();

        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_STATIC, "");
        instance.installModule({ moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback });

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
        _testIsValidSignature("Permit(bytes32 stuff)", "Permit", true);
    }

    // By right, this should be a proper domain separator, but I'm lazy.

    function _testIsValidSignature(bytes memory contentsType, bytes memory contentsName, bool success) internal {
        bytes32 contents = keccak256(abi.encode("random", contentsType));
        console2.log("contents");
        console2.logBytes32(contents);

        _TestTemps memory t = _testTemps(sessionSigner1);
        // (t.signer, t.privateKey) = _randomSigner();

        bytes32 hash = _toERC1271Hash(address(t.account), contents, contentsType, contentsName);
        console2.log("---------");
        console2.logBytes32(hash);
        (t.v, t.r, t.s) = vm.sign(t.privateKey, hash);

        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);

        bytes memory signature = abi.encodePacked(
            t.r, t.s, t.v, appDomainSeparator, contents, contentsDescription, uint16(contentsDescription.length)
        );
        signature = abi.encodePacked(permissionId, signature);
        signature = _erc6492Wrap(signature);

        // signature = abi.encodePacked(permissionId, signature);
        // Success returns `0x1626ba7e`.
        assertEq(
            IERC1271(t.account).isValidSignature(
                _toContentsHash(contents), abi.encodePacked(address(smartSession), signature)
            ),
            success ? bytes4(0x1626ba7e) : bytes4(0xffffffff),
            "invalid sig"
        );
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
        bytes memory contentsType,
        bytes memory contentsName
    )
        internal
        view
        returns (bytes32)
    {
        bytes32 parentStructHash = keccak256(
            abi.encodePacked(
                abi.encode(_typedDataSignTypeHash(contentsType, contentsName), contents),
                _accountDomainStructFields(account)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", appDomainSeparator, parentStructHash));
    }

    struct _AccountDomainStruct {
        string name;
        string version;
        uint256 chainId;
        address verifyingContract;
        bytes32 salt;
    }

    function _accountDomainStructFields(address account) internal view returns (bytes memory) {
        _AccountDomainStruct memory t;
        (, t.name, t.version, t.chainId, t.verifyingContract, t.salt,) = EIP712(account).eip712Domain();

        return abi.encode(keccak256(bytes(t.name)), keccak256(bytes(t.version)), t.chainId, t.verifyingContract, t.salt);
    }

    function _typedDataSignTypeHash(
        bytes memory contentsType,
        bytes memory contentsName
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                "TypedDataSign(",
                contentsName,
                " contents,string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
                contentsType
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

    function _toContentsHash(bytes32 contents) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", appDomainSeparator, contents));
    }
}
