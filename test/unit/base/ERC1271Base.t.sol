import "../../Base.t.sol";
import { ISmartSession } from "contracts/ISmartSession.sol";
import { SmartSessionCompatibilityFallback } from "contracts/SmartSessionCompatibilityFallback.sol";
import { EIP712 } from "solady/utils/EIP712.sol";
import { LibString } from "solady/utils/LibString.sol";
import { MODULE_TYPE_FALLBACK } from "modulekit/external/ERC7579.sol";
import { CALLTYPE_SINGLE } from "modulekit/external/ERC7579.sol";

contract ERC1271TestBase is BaseTest {
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

    SmartSessionCompatibilityFallback fallbackModule;

    bytes32 appDomainSeparator;

    function setUp() public virtual override {
        super.setUp();

        fallbackModule = new SmartSessionCompatibilityFallback();
        bytes memory _fallback = abi.encode(EIP712.eip712Domain.selector, CALLTYPE_SINGLE, "");
        instance.installModule({ moduleTypeId: MODULE_TYPE_FALLBACK, module: address(fallbackModule), data: _fallback });

        EIP712Domain memory domain = EIP712Domain({
            name: "Forge",
            version: "1",
            chainId: 1,
            verifyingContract: address(0x6605F8785E09a245DD558e55F9A0f4A508434503)
        });
        appDomainSeparator = hash(domain);
    }

    function _testIsValidSignature(
        bytes memory contentsType,
        bytes memory contentsName,
        bool expectSuccess,
        PermissionId permissionId,
        bool is6492,
        Account memory sessionSigner
    )
        internal
    {
        bytes32 contents = keccak256(abi.encode("random", contentsType));

        _TestTemps memory t = _testTemps(sessionSigner);
        (t.v, t.r, t.s) =
            vm.sign(t.privateKey, _toERC1271Hash(address(t.account), contents, contentsType, contentsName));

        bytes memory contentsDescription = abi.encodePacked(contentsType, contentsName);

        bytes memory signature = abi.encodePacked(
            t.r, t.s, t.v, appDomainSeparator, contents, contentsDescription, uint16(contentsDescription.length)
        );
        signature = abi.encodePacked(permissionId, signature);
        if (is6492) {
            signature = _erc6492Wrap(signature);
        }

        // Success returns `0x1626ba7e`.
        assertEq(
            IERC1271(t.account).isValidSignature(
                _toContentsHash(contents), abi.encodePacked(address(smartSession), signature)
            ),
            expectSuccess ? bytes4(0x1626ba7e) : bytes4(0xffffffff)
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
        bytes1 fields;
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

    function _toContentsHash(bytes32 contents) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", appDomainSeparator, contents));
    }
}
