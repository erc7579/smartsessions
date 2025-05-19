// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { Test, Vm, console2 } from "forge-std/Test.sol";
import { MultiKeySigner } from "../../contracts/external/wc-cosigner/MultiKeySigner.sol";
import { Signer, SignerType, SignerEncode } from "../../contracts/external/wc-cosigner/libs/SignerEncode.sol";
import { WebAuthnValidatorData } from "../../contracts/external/wc-cosigner/libs/PasskeyHelper.sol";
import { WebAuthn } from "webauthn-sol/WebAuthn.sol";

contract MultiKeySignerFuzzTest is Test {
    using SignerEncode for Signer[];

    uint256 internal constant _MAX_SIGNERS = 3; // Max number of signers to fuzz
    uint256 internal constant _MIN_AUTHDATA_LEN = 37;
    uint256 internal constant _MAX_AUTHDATA_LEN_FUZZ = 128; // Max length for fuzzed authenticatorData
    uint256 internal constant _MAX_CLIENTJSON_LEN_FUZZ = 256; // Max length for fuzzed clientDataJSON
    uint256 internal constant _EOA_SIG_LEN = 65;

    // Struct to hold components for passkey signature
    struct _PasskeySignatureComponents {
        uint256 pkX;
        uint256 pkY;
        bytes authData;
        string clientJson;
        uint256 challengeIndex;
        uint256 typeIndex;
        uint256 r;
        uint256 s;
    }

    // Helper to slice bytes from a larger bytes array
    function _slice(bytes calldata _data, uint256 _start, uint256 _length) internal pure returns (bytes memory) {
        // Assumes _start + _length is within bounds, checked by caller with vm.assume
        bytes memory b = new bytes(_length);
        for (uint256 i = 0; i < _length; i++) {
            b[i] = _data[_start + i];
        }
        return b;
    }

    function _readUint256FromBlob(bytes calldata blob, uint256 offset) internal pure returns (uint256 val) {
        // Assumes offset + 32 is within bounds
        bytes memory b = _slice(blob, offset, 32);
        val = abi.decode(b, (uint256));
    }

    function _readAddressFromBlob(bytes calldata blob, uint256 offset) internal pure returns (address val) {
        // Assumes offset + 20 is within bounds
        bytes memory b = _slice(blob, offset, 20);
        val = address(bytes20(b));
    }

    // Helper to read passkey components from creationBlob
    function _readPasskeyComponents(
        bytes calldata creationBlob,
        uint256 initialOffset
    )
        internal
        pure
        returns (_PasskeySignatureComponents memory components, uint256 newOffset)
    {
        uint256 offset = initialOffset;

        // pubKeyX
        vm.assume(offset + 32 <= creationBlob.length);
        components.pkX = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        // pubKeyY
        vm.assume(offset + 32 <= creationBlob.length);
        components.pkY = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        // authData
        vm.assume(offset < creationBlob.length); // For authData len byte
        uint256 authDataLenPart = uint8(creationBlob[offset]) % (_MAX_AUTHDATA_LEN_FUZZ - _MIN_AUTHDATA_LEN + 1);
        uint256 authDataLen = authDataLenPart + _MIN_AUTHDATA_LEN;
        offset++;
        vm.assume(offset + authDataLen <= creationBlob.length);
        components.authData = _slice(creationBlob, offset, authDataLen);
        offset += authDataLen;

        // clientDataJSON
        vm.assume(offset < creationBlob.length); // For clientDataJSON len byte
        uint256 clientJsonLen = uint8(creationBlob[offset]) % (_MAX_CLIENTJSON_LEN_FUZZ + 1);
        offset++;
        vm.assume(offset + clientJsonLen <= creationBlob.length);
        bytes memory clientJsonBytes = _slice(creationBlob, offset, clientJsonLen);
        components.clientJson = string(clientJsonBytes); // Can be empty
        offset += clientJsonLen;

        // challengeIndex
        vm.assume(offset + 32 <= creationBlob.length);
        components.challengeIndex = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        // typeIndex
        vm.assume(offset + 32 <= creationBlob.length);
        components.typeIndex = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        // r
        vm.assume(offset + 32 <= creationBlob.length);
        components.r = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        // s
        vm.assume(offset + 32 <= creationBlob.length);
        components.s = _readUint256FromBlob(creationBlob, offset);
        offset += 32;

        newOffset = offset;
    }

    /// @dev Fuzz test for MultiKeySigner.validateSignatureWithData using a creationBlob.
    function testFuzzMultiKeySignerValidateSignatureWithData(
        bytes32 userOpHash,
        uint8 numSignersRaw,
        bytes calldata creationBlob
    )
        public
    {
        uint256 numSigners = numSignersRaw % (_MAX_SIGNERS + 1);

        // Estimate minimum blob length: 1 byte for type choice per signer.
        // More precise check is done at each read.
        vm.assume(creationBlob.length >= numSigners && creationBlob.length < 4096);

        Signer[] memory signers = new Signer[](numSigners);
        bytes[] memory signatureBlobs = new bytes[](numSigners);
        uint256 offset = 0;

        for (uint256 i = 0; i < numSigners; i++) {
            vm.assume(offset < creationBlob.length); // Need at least 1 byte for type choice
            uint8 typeChoice = uint8(creationBlob[offset]);
            offset++;

            if (typeChoice % 2 == 0) {
                // Arbitrary choice for EOA
                // EOA Signer
                vm.assume(offset + 20 <= creationBlob.length); // For address
                address eoaAddr = _readAddressFromBlob(creationBlob, offset);
                offset += 20;

                signers[i] = Signer({ signerType: SignerType.EOA, data: abi.encodePacked(eoaAddr) });

                vm.assume(offset + _EOA_SIG_LEN <= creationBlob.length); // For EOA signature
                signatureBlobs[i] = _slice(creationBlob, offset, _EOA_SIG_LEN);
                offset += _EOA_SIG_LEN;
            } else {
                // Passkey Signer
                _PasskeySignatureComponents memory components;
                (components, offset) = _readPasskeyComponents(creationBlob, offset);

                signers[i] = Signer({
                    signerType: SignerType.PASSKEY,
                    data: abi.encode(WebAuthnValidatorData({ pubKeyX: components.pkX, pubKeyY: components.pkY }))
                });

                signatureBlobs[i] = abi.encode(
                    WebAuthn.WebAuthnAuth({
                        authenticatorData: components.authData,
                        clientDataJSON: components.clientJson,
                        challengeIndex: components.challengeIndex,
                        typeIndex: components.typeIndex,
                        r: components.r,
                        s: components.s
                    })
                );
            }
        }

        bytes memory moduleData = signers.encodeSignersInternal();
        bytes memory sigToValidate = abi.encode(signatureBlobs);

        MultiKeySigner mkSigner = new MultiKeySigner();

        try mkSigner.validateSignatureWithData(userOpHash, sigToValidate, moduleData) returns (bool res) {
            if (numSigners == 0) {
                assertTrue(res, "validateSignatureWithData should return true for zero signers");
            } else {
                // For random inputs with numSigners > 0, we expect false or revert.
                // If res is true, it's an unexpected success.
                if (res) {
                    console2.log("--- Fuzz Test Unexpectedly Returned True ---");
                    console2.logBytes32(userOpHash);
                    console2.logUint(numSigners);
                    // Log more details if needed
                    assertFalse(true, "validateSignatureWithData returned true for random non-empty inputs");
                }
                // If res is false, it's an acceptable outcome.
            }
        } catch Error(string memory reason) {
            // Revert with reason string is acceptable.
            // console.log("Reverted with reason:", reason);
        } catch Panic(uint256 code) {
            // Revert with panic code is acceptable.
            // console.log("Reverted with panic code:", code);
        } catch (bytes memory lowLevelData) {
            // Any other revert (e.g., empty revert) is also acceptable.
            // console.logBytes(lowLevelData);
        }
    }
}
