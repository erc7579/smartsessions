// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Test } from "forge-std/Test.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

import { SubModuleLib } from "contracts/lib/SubModuleLib.sol";
import { MultiKeySigner, ISessionValidator } from "contracts/external/wc-cosigner/MultiKeySigner.sol";
import { SignerEncode, Signer, SignerType } from "contracts/external/wc-cosigner/libs/SignerEncode.sol";
import { PasskeyHelper, WebAuthnValidatorData } from "contracts/external/wc-cosigner/libs/PasskeyHelper.sol";
import { ERC7579_MODULE_TYPE_STATELESS_VALIDATOR } from "contracts/DataTypes.sol";

import { WebAuthn } from "webauthn-sol/WebAuthn.sol";
import { Base64Url } from "FreshCryptoLib/utils/Base64Url.sol";

contract MultiKeySignerTest is Test {
    using PasskeyHelper for *;
    using SubModuleLib for *;
    using SignerEncode for *;

    MultiKeySigner internal mkSigner;

    // EOA accounts
    uint256 internal alicePk = 0xA11CE;
    address internal aliceAddr = vm.addr(alicePk);
    uint256 internal bobPk = 0xB0B;
    address internal bobAddr = vm.addr(bobPk);

    // Passkey data (values adapted from user's WebAuthnTest.sol - chrome test)
    WebAuthnValidatorData internal passkeyDefaultData;
    bytes internal passkeyDefaultAuthenticatorData;
    string internal passkeyClientDataJSONTemplate = '{"type":"webauthn.get","challenge":"<CHALLENGE_PLACEHOLDER>",'
        '"origin":"http://localhost:3005","crossOrigin":false}';
    uint256 internal passkeyDefaultR;
    uint256 internal passkeyDefaultS;
    uint256 internal passkeyChallengeIndex = 23;
    uint256 internal passkeyTypeIndex = 1;

    // Default challenge for which the passkeyDefaultR, passkeyDefaultS are valid.
    // From user's WebAuthnTest.sol (challenge value used below)
    bytes32 internal constant DEFAULT_USER_OP_HASH_FOR_PASSKEY =
        0xf631058a3ba1116acce12396fad0a125b5041c43f8e15723709f81aa8d5f4ccf;

    function setUp() public {
        // Deploy MultiKeySigner
        mkSigner = new MultiKeySigner();

        // Initialize Passkey Test Data (values from user's WebAuthnTest.sol - chrome test)
        passkeyDefaultData = WebAuthnValidatorData({
            pubKeyX: 28_573_233_055_232_466_711_029_625_910_063_034_642_429_572_463_461_595_413_086_259_353_299_906_450_061,
            pubKeyY: 39_367_742_072_897_599_771_788_408_398_752_356_480_431_855_827_262_528_811_857_788_332_151_452_825_281
        });
        passkeyDefaultAuthenticatorData =
            hex"49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763050000010a";
        passkeyDefaultR =
            29_739_767_516_584_490_820_047_863_506_833_955_097_567_272_713_519_339_793_744_591_468_032_609_909_569;
        passkeyDefaultS =
            45_947_455_641_742_997_809_691_064_512_762_075_989_493_430_661_170_736_817_032_030_660_832_793_108_102;
    }

    // --- Helper Functions ---

    function _encodeSignerArray(Signer[] memory signers) internal pure returns (bytes memory) {
        // Directly use the public encodeSigners from the MultiKeySigner contract if possible,
        // or the library function for testing encoding logic.
        // For preparing `data` for `validateSignatureWithData`, we use `mkSigner.encodeSigners`
        // or `SignerEncode.encodeSignersInternal`
        return SignerEncode.encodeSignersInternal(signers);
    }

    // Helper functions to bridge bytes memory to bytes calldata for SignerEncode.decodeSigners
    function _decodeSignersViaCalldata(bytes memory encodedData) internal view returns (Signer[] memory) {
        return this.externalCallDecode(encodedData);
    }

    function externalCallDecode(bytes calldata data) external pure returns (Signer[] memory) {
        return data.decodeSigners();
    }

    function _encodeSignatures(bytes[] memory sigs) internal pure returns (bytes memory) {
        return abi.encode(sigs);
    }

    function _getEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return ECDSA.toEthSignedMessageHash(hash);
    }

    function _signWithEoa(bytes32 hash, uint256 privateKey) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, hash);
        return abi.encodePacked(r, s, v);
    }

    // Helper to create the passkey signature blob, now structured as WebAuthn.WebAuthnAuth
    function _createPasskeySignatureBlob(bytes32 userOpHashOrChallenge) internal view returns (bytes memory) {
        // The challenge in clientDataJSON must be the base64url encoding of the raw challenge bytes.
        // In WebAuthn.sol, verify() takes `bytes memory challenge` (raw bytes).
        // Here, userOpHashOrChallenge is the raw challenge (often a bytes32 hash).
        string memory actualChallengeBase64URL = Base64Url.encode(
            abi.encode(userOpHashOrChallenge) // abi.encode to get bytes from bytes32
        );

        string memory clientDataJSON =
            _replace(passkeyClientDataJSONTemplate, "<CHALLENGE_PLACEHOLDER>", actualChallengeBase64URL);

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            authenticatorData: passkeyDefaultAuthenticatorData,
            clientDataJSON: clientDataJSON,
            challengeIndex: passkeyChallengeIndex,
            typeIndex: passkeyTypeIndex,
            r: passkeyDefaultR,
            s: passkeyDefaultS
        });

        return abi.encode(auth);
    }

    function substring(string memory str, uint256 startIndex, uint256 endIndex) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory result = new bytes(endIndex - startIndex);
        for (uint256 i = startIndex; i < endIndex; i++) {
            result[i - startIndex] = strBytes[i];
        }
        return string(result);
    }

    // String replace helper (basic)
    function _replace(string memory str, string memory from, string memory to) internal pure returns (string memory) {
        bytes memory strBytes = bytes(str);
        bytes memory fromBytes = bytes(from);
        bytes memory toBytes = bytes(to);

        if (fromBytes.length == 0) return str;
        if (strBytes.length < fromBytes.length) return str; // Cannot find 'from' if 'str' is shorter

        // Calculate the length of the result string
        // This part is a bit tricky due to potential multiple occurrences and different lengths of 'from' and 'to'
        // For simplicity in this refactor, we'll build an intermediate parts array.
        // A more gas-efficient way for on-chain use would pre-calculate the exact length.

        bytes memory resultBuilder; // Using a dynamic bytes array to build the result

        uint256 k = 0; // Current position in strBytes
        while (k < strBytes.length) {
            bool isMatch = true;
            if (k + fromBytes.length <= strBytes.length) {
                for (uint256 j = 0; j < fromBytes.length; j++) {
                    if (strBytes[k + j] != fromBytes[j]) {
                        isMatch = false;
                        break;
                    }
                }
            } else {
                isMatch = false;
            }

            if (isMatch) {
                resultBuilder = abi.encodePacked(resultBuilder, toBytes);
                k += fromBytes.length;
            } else {
                resultBuilder = abi.encodePacked(resultBuilder, strBytes[k]);
                k++;
            }
        }
        return string(resultBuilder);
    }

    // --- Basic Module Information Tests ---

    function test_onInstall_emptyData_succeeds() public {
        mkSigner.onInstall("");
        // No revert expected, implicit pass
    }

    function test_RevertWhen_onInstall_withData() public {
        vm.expectRevert(MultiKeySigner.InstallationDataNotSupported.selector);
        mkSigner.onInstall(hex"0123");
    }

    function test_onUninstall_doesNotRevert() public {
        mkSigner.onUninstall(""); // Should not revert
        mkSigner.onUninstall(hex"0123"); // Should not revert
            // Implicit pass if no revert
    }

    function test_isModuleType_withValidatorType_returnsTrue() public view {
        assertTrue(mkSigner.isModuleType(ERC7579_MODULE_TYPE_STATELESS_VALIDATOR), "Should be stateless validator type");
    }

    function test_isModuleType_withOtherType_returnsFalse() public view {
        assertFalse(mkSigner.isModuleType(0), "Should not be validator type for 0");
        assertFalse(mkSigner.isModuleType(12_345), "Should not be validator type for 12345");
    }

    function test_supportsInterface_withISessionValidator_returnsTrue() public view {
        assertTrue(
            mkSigner.supportsInterface(type(ISessionValidator).interfaceId),
            "Should support ISessionValidator interface"
        );
    }

    function test_supportsInterface_withRandomInterface_returnsFalse() public view {
        assertFalse(
            mkSigner.supportsInterface(bytes4(keccak256("randomInterface()"))), "Should not support random interface"
        );
        assertFalse(mkSigner.supportsInterface(0xffffffff), "Should not support 0xffffffff interface");
    }

    function test_isInitialized_alwaysReturnsTrue() public view {
        assertTrue(
            mkSigner.isInitialized(address(0)), "isInitialized should always return true for stateless validator"
        );
        assertTrue(mkSigner.isInitialized(aliceAddr), "isInitialized should always return true, regardless of address");
    }

    // --- SignerEncode Tests (via MultiKeySigner.encodeSigners and direct if needed) ---

    function test_encodeSigners_withEmptyArray_succeeds() public view {
        Signer[] memory signers = new Signer[](0);
        bytes memory encodedData = mkSigner.encodeSigners(signers);
        assertEq(encodedData.length, 1, "Encoded empty signers length");
        assertEq(uint8(encodedData[0]), 0, "Encoded empty signers byte content");

        Signer[] memory decodedSigners = _decodeSignersViaCalldata(encodedData);
        assertEq(decodedSigners.length, 0, "Decoded empty signers length");
    }

    function test_encodeDecode_withSingleEoa_succeeds() public view {
        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });

        bytes memory encodedData = mkSigner.encodeSigners(signers);
        assertEq(encodedData.length, 1 + 1 + 20, "Encoded single EOA length");
        assertEq(uint8(encodedData[0]), 1, "Signer array length in encoded data");
        assertEq(uint8(encodedData[1]), uint8(SignerType.EOA), "Signer type EOA in encoded data");

        (Signer[] memory decodedSigners) = _decodeSignersViaCalldata(encodedData);
        assertEq(decodedSigners.length, 1, "Decoded single EOA length");
        assertEq(uint8(decodedSigners[0].signerType), uint8(SignerType.EOA), "Decoded EOA signer type");
        assertEq(SignerEncode.decodeEOA(decodedSigners[0]), aliceAddr, "Decoded EOA address");
    }

    function test_encodeDecode_withSinglePasskey_succeeds() public view {
        Signer[] memory signers = new Signer[](1);
        // Create dummy WebAuthnValidatorData for encoding test; contents don't matter for encoding structure
        WebAuthnValidatorData memory pkData = WebAuthnValidatorData({ pubKeyX: 123, pubKeyY: 456 });
        signers[0] = Signer({
            signerType: SignerType.PASSKEY,
            data: abi.encode(pkData) // WebAuthnValidatorData is a struct, abi.encode it
         });

        bytes memory encodedData = mkSigner.encodeSigners(signers);
        assertEq(encodedData.length, 1 + 1 + 64, "Encoded single Passkey length");
        assertEq(uint8(encodedData[0]), 1, "Signer array length for Passkey");
        assertEq(uint8(encodedData[1]), uint8(SignerType.PASSKEY), "Signer type Passkey in encoded data");

        (Signer[] memory decodedSigners) = _decodeSignersViaCalldata(encodedData);
        assertEq(decodedSigners.length, 1, "Decoded single Passkey length");
        assertEq(uint8(decodedSigners[0].signerType), uint8(SignerType.PASSKEY), "Decoded Passkey signer type");
        WebAuthnValidatorData memory decodedPkData = SignerEncode.decodePasskey(decodedSigners[0]);
        assertEq(decodedPkData.pubKeyX, 123, "Decoded Passkey pubKeyX");
        assertEq(decodedPkData.pubKeyY, 456, "Decoded Passkey pubKeyY");
    }

    function test_encodeDecode_withMultipleSigners_succeeds() public view {
        Signer[] memory signers = new Signer[](2);
        WebAuthnValidatorData memory pkData = WebAuthnValidatorData({ pubKeyX: 789, pubKeyY: 101 });
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        signers[1] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(pkData) });

        bytes memory encodedData = mkSigner.encodeSigners(signers);
        assertEq(encodedData.length, 1 + (1 + 20) + (1 + 64), "Encoded multiple signers length");
        assertEq(uint8(encodedData[0]), 2, "Signer array length for multiple signers");

        (Signer[] memory decodedSigners) = _decodeSignersViaCalldata(encodedData);
        assertEq(decodedSigners.length, 2, "Decoded multiple signers length");
        assertEq(uint8(decodedSigners[0].signerType), uint8(SignerType.EOA), "Decoded signer 0 type (EOA)");
        assertEq(SignerEncode.decodeEOA(decodedSigners[0]), aliceAddr, "Decoded signer 0 EOA address");
        assertEq(uint8(decodedSigners[1].signerType), uint8(SignerType.PASSKEY), "Decoded signer 1 type (Passkey)");
        WebAuthnValidatorData memory decodedPkData = SignerEncode.decodePasskey(decodedSigners[1]);
        assertEq(decodedPkData.pubKeyX, 789, "Decoded signer 1 Passkey pubKeyX");
        assertEq(decodedPkData.pubKeyY, 101, "Decoded signer 1 Passkey pubKeyY");
    }

    function test_RevertWhen_decodeSigners_withInvalidType() public {
        bytes memory malformedData = abi.encodePacked(uint8(1), uint8(99), bytes20(0));
        vm.expectRevert(SignerEncode.UnknownSignerType.selector);
        _decodeSignersViaCalldata(malformedData);
    }

    // --- validateSignatureWithData Tests - EOA ---

    function test_validateSignatureWithData_withSingleValidEoaSignature_returnsTrue() public view {
        bytes32 userOpHash = keccak256("test_user_op_hash_eoa_valid");
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signWithEoa(ethSignedHash, alicePk);
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, true, "Valid single EOA signature should pass");
    }

    function test_validateSignatureWithData_withSingleEoa_invalidSignatureWrongSigner_returnsFalse() public view {
        bytes32 userOpHash = keccak256("test_user_op_hash_eoa_invalid_signer");
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](1);
        // Expecting Alice to sign, but Bob actually signs
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signWithEoa(ethSignedHash, bobPk); // Bob signs
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Invalid EOA signature (wrong signer) should fail");
    }

    function test_validateSignatureWithData_withSingleEoa_invalidSignatureDataPointsToWrongSigner_returnsFalse()
        public
        view
    {
        bytes32 userOpHash = keccak256("test_user_op_hash_eoa_data_wrong_signer");
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](1);
        // Data says Bob should sign, but Alice signs
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(bobAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signWithEoa(ethSignedHash, alicePk); // Alice signs
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Invalid EOA signature (signerData points to wrong EOA) should fail");
    }

    function test_validateSignatureWithData_withSingleEoa_invalidSignatureWrongHash_returnsFalse() public view {
        bytes32 userOpHash = keccak256("test_user_op_hash_eoa_wrong_hash_1");
        bytes32 wrongUserOpHash = keccak256("test_user_op_hash_eoa_wrong_hash_2");
        bytes32 ethSignedHashForSigning = _getEthSignedMessageHash(wrongUserOpHash);

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](1);
        // Sign the wrong hash
        signatures[0] = _signWithEoa(ethSignedHashForSigning, alicePk);
        bytes memory sigData = _encodeSignatures(signatures);

        // Validate against the original userOpHash
        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Invalid EOA signature (signed wrong hash) should fail");
    }

    // --- validateSignatureWithData Tests - Passkey ---

    function test_validateSignatureWithData_withSingleValidPasskeySignature_returnsTrue() public view {
        // Use the default userOpHash/challenge for which the default passkey signature is valid.
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        // Create signature blob for the userOpHash
        bytes memory passkeySigBlob = _createPasskeySignatureBlob(userOpHash);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = passkeySigBlob;
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, true, "Valid Passkey signature should pass");
    }

    function test_validateSignatureWithData_withSinglePasskey_invalidSignatureTampered_returnsFalse() public view {
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        // Create original blob
        bytes memory originalPasskeySigBlob = _createPasskeySignatureBlob(userOpHash);

        // Decode, tamper, and re-encode the WebAuthn.WebAuthnAuth struct
        WebAuthn.WebAuthnAuth memory authStruct = abi.decode(originalPasskeySigBlob, (WebAuthn.WebAuthnAuth));

        // Tamper one of the signature components, e.g., r
        authStruct.r = authStruct.r + 1;

        bytes memory tamperedPasskeySigBlob = abi.encode(authStruct);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = tamperedPasskeySigBlob;
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Tampered Passkey signature should fail");
    }

    function test_validateSignatureWithData_withSinglePasskey_wrongPublicKeyInSignerData_returnsFalse() public view {
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;

        WebAuthnValidatorData memory wrongPasskeyData = WebAuthnValidatorData({ pubKeyX: 1, pubKeyY: 2 });

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(wrongPasskeyData) });
        bytes memory signerData = _encodeSignerArray(signers);

        // Signature is for the default public key, generated with DEFAULT_USER_OP_HASH_FOR_PASSKEY
        bytes memory passkeySigBlob = _createPasskeySignatureBlob(userOpHash);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = passkeySigBlob;
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Passkey sig with wrong pubkey in signer data should fail");
    }

    function test_validateSignatureWithData_withSinglePasskey_challengeMismatch_returnsFalse() public view {
        // This is the hash that validateSignatureWithData will use as the expected challenge.
        bytes32 userOpHashForValidation = keccak256(abi.encodePacked("passkey_challenge_mismatch_validation_hash_new"));

        // The signature blob, however, is created for `DEFAULT_USER_OP_HASH_FOR_PASSKEY`.
        bytes32 challengeForBlobCreation = DEFAULT_USER_OP_HASH_FOR_PASSKEY;

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        // Create signature blob with clientDataJSON referring to `challengeForBlobCreation`
        bytes memory passkeySigBlob = _createPasskeySignatureBlob(challengeForBlobCreation);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = passkeySigBlob;
        bytes memory sigData = _encodeSignatures(signatures);

        // Validate against `userOpHashForValidation`. This should fail because the challenge
        // embedded in the blob's clientDataJSON (derived from `challengeForBlobCreation`)
        // will not match `userOpHashForValidation`.
        bool result = mkSigner.validateSignatureWithData(userOpHashForValidation, sigData, signerData);
        assertEq(result, false, "Passkey sig with challenge mismatch should fail");
    }

    // --- validateSignatureWithData Tests - Mixed Signers ---

    function test_validateSignatureWithData_withMixedSigners_eoaValid_passkeyValid_returnsTrue() public view {
        // Use DEFAULT_USER_OP_HASH_FOR_PASSKEY for the Passkey part's challenge.
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;
        // EOA part will sign the ethSignedMessageHash of this userOpHash.
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](2);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        signers[1] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signWithEoa(ethSignedHash, alicePk);
        signatures[1] = _createPasskeySignatureBlob(userOpHash); // Passkey blob created with raw userOpHash challenge
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, true, "Mixed (Valid EOA + Valid Passkey) should succeed");
    }

    function test_validateSignatureWithData_withMixedSigners_eoaValid_passkeyInvalid_returnsFalse() public view {
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](2);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        signers[1] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes memory validPasskeyBlob = _createPasskeySignatureBlob(userOpHash);
        WebAuthn.WebAuthnAuth memory authStruct = abi.decode(validPasskeyBlob, (WebAuthn.WebAuthnAuth));
        authStruct.s = authStruct.s - 1; // Tamper passkey sig component
        bytes memory invalidPasskeyBlob = abi.encode(authStruct);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signWithEoa(ethSignedHash, alicePk);
        signatures[1] = invalidPasskeyBlob;
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Mixed (Valid EOA + Invalid Passkey) should fail");
    }

    function test_validateSignatureWithData_withMixedSigners_eoaInvalid_passkeyValid_returnsFalse() public view {
        bytes32 userOpHash = DEFAULT_USER_OP_HASH_FOR_PASSKEY;
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](2);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) }); // Alice is expected
        signers[1] = Signer({ signerType: SignerType.PASSKEY, data: abi.encode(passkeyDefaultData) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signWithEoa(ethSignedHash, bobPk); // Invalid EOA sig (signed by Bob)
        signatures[1] = _createPasskeySignatureBlob(userOpHash); // Valid passkey blob
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, false, "Mixed (Invalid EOA + Valid Passkey) should fail");
    }

    // --- validateSignatureWithData Tests - Edge Cases ---

    function test_validateSignatureWithData_withEmptySignersAndSignatures_returnsTrue() public view {
        bytes32 userOpHash = keccak256(abi.encodePacked("empty_signers_test"));

        Signer[] memory signers = new Signer[](0);
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](0);
        bytes memory sigData = _encodeSignatures(signatures);

        bool result = mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
        assertEq(result, true, "Empty signers and signatures should succeed (validate nothing)");
    }

    function test_RevertWhen_validateSignatureWithData_lengthMismatch_signatureArrayShorter() public {
        bytes32 userOpHash = keccak256(abi.encodePacked("length_mismatch_shorter_sig"));

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](0); // Sig array is shorter
        bytes memory sigData = _encodeSignatures(signatures);

        vm.expectRevert(MultiKeySigner.InvalidSignatureLength.selector);
        mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
    }

    function test_RevertWhen_validateSignatureWithData_lengthMismatch_signatureArrayLonger() public {
        bytes32 userOpHash = keccak256(abi.encodePacked("length_mismatch_longer_sig"));
        bytes32 ethSignedHash = _getEthSignedMessageHash(userOpHash);

        Signer[] memory signers = new Signer[](1);
        signers[0] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(aliceAddr) });
        bytes memory signerData = _encodeSignerArray(signers);

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signWithEoa(ethSignedHash, alicePk);
        signatures[1] = _signWithEoa(ethSignedHash, bobPk); // Extra signature
        bytes memory sigData = _encodeSignatures(signatures);

        vm.expectRevert(MultiKeySigner.InvalidSignatureLength.selector);
        mkSigner.validateSignatureWithData(userOpHash, sigData, signerData);
    }

    function test_RevertWhen_validateSignatureWithData_unknownSignerTypeInSignerData() public {
        bytes32 userOpHash = keccak256(abi.encodePacked("unknown_signer_type_test"));

        // Manually craft signer data with an invalid type
        // Signer array of length 1
        // SignerType = 99 (invalid)
        // Data = 20 bytes of zero (doesn't matter as type check fails first)
        bytes memory malformedSignerData = abi.encodePacked(uint8(1), uint8(99), bytes20(0));

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = hex"00"; // Dummy signature, won't be reached
        bytes memory sigData = _encodeSignatures(signatures);

        vm.expectRevert(SignerEncode.UnknownSignerType.selector);
        // This revert comes from SignerEncode.decodeSigners directly when it encounters an unknown type,
        // as it cannot determine the length of the data to skip.
        // MultiKeySigner.validateSignatureWithData's InvalidSignatureType would only be hit if decoding somehow
        // succeeded
        // but the type was still not one of the recognized SignerType enums.
        mkSigner.validateSignatureWithData(userOpHash, sigData, malformedSignerData);
    }
}
