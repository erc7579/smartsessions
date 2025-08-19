// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { WebAuthnValidatorData } from "./PasskeyHelper.sol";

/// @notice Defines the type of signer.
enum SignerType {
    EOA, // External Owned Account
    PASSKEY // WebAuthn Passkey

}

/// @notice Represents a signer with its type and associated data.
struct Signer {
    /// @dev The type of the signer (EOA or PASSKEY).
    SignerType signerType;
    /// @dev The data associated with the signer (e.g., address for EOA, WebAuthn data for Passkey).
    bytes data;
}

/// @title SignerEncode
/// @author [alphabetically] Filipp Makarov (Biconomy) & zeroknots.eth (Rhinestone)
///
/// @notice Library for encoding and decoding Signer structs.
library SignerEncode {
    error UnknownSignerType();

    /// @notice Decodes EOA signer data to an address.
    /// @param signer The Signer struct containing EOA data.
    /// @return eoa The decoded EOA address.
    function decodeEOA(Signer memory signer) internal pure returns (address) {
        return address(bytes20(signer.data));
    }

    /// @notice Decodes Passkey signer data to WebAuthnValidatorData.
    /// @param signer The Signer struct containing Passkey data.
    /// @return passkey The decoded WebAuthnValidatorData.
    function decodePasskey(Signer memory signer) internal pure returns (WebAuthnValidatorData memory) {
        return abi.decode(signer.data, (WebAuthnValidatorData));
    }

    /// @notice Encodes an array of Signer structs into a byte array.
    /// @dev Internal function to handle the encoding logic.
    /// @param signers Array of Signer structs to encode.
    /// @return encoded The abi encoded byte array of signers.
    function encodeSignersInternal(Signer[] memory signers) internal pure returns (bytes memory) {
        uint256 length = signers.length;
        bytes memory encoded = abi.encodePacked(uint8(length));
        for (uint256 i = 0; i < length; i++) {
            encoded = abi.encodePacked(encoded, uint8(signers[i].signerType));
            encoded = abi.encodePacked(encoded, signers[i].data);
        }
        return encoded;
    }

    /// @notice Decodes a byte array into an array of Signer structs.
    /// @dev Reverts with UnknownSignerType if an invalid signerType is encountered.
    /// @param data The abi encoded byte array of signers.
    /// @return signers Array of decoded Signer structs.
    function decodeSigners(bytes calldata data) internal pure returns (Signer[] memory signers) {
        uint256 length = uint256(uint8(bytes1(data[0])));
        signers = new Signer[](length);
        uint256 offset = 1;
        for (uint256 i = 0; i < length; i++) {
            uint8 signerTypeByte = uint8(bytes1(data[offset]));
            offset++;
            uint256 dataLength;
            if (signerTypeByte == uint8(SignerType.EOA)) {
                dataLength = 20;
            } else if (signerTypeByte == uint8(SignerType.PASSKEY)) {
                dataLength = 64;
            } else {
                revert UnknownSignerType();
            }
            bytes memory signerData = data[offset:offset + dataLength];
            offset += dataLength;
            signers[i] = Signer(SignerType(signerTypeByte), signerData);
        }
        return signers;
    }
}
