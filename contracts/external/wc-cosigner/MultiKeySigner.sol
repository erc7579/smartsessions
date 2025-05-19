// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

// External Dependencies
import { ECDSA } from "solady/utils/ECDSA.sol";

// Local Project Files
import { ERC7579_MODULE_TYPE_STATELESS_VALIDATOR } from "../../DataTypes.sol";
import { PasskeyHelper, WebAuthnValidatorData } from "./libs/PasskeyHelper.sol";
import { ISessionValidator } from "contracts/interfaces/ISessionValidator.sol";
import { SignerEncode, Signer, SignerType } from "./libs/SignerEncode.sol";

/// @title MultiKeySigner - Stateless Session Validator for ERC-7579
/// @author [alphabetically] Filipp Makarov (Biconomy), rplusq (Reown) & zeroknots.eth (Rhinestone)

/// @notice This contract is an ERC-7579 compliant stateless session validator module,
///         designed for use with the Smart Sessions framework. It enables signature validation
///         for sessions using multiple signer types, such as EOA and WebAuthn Passkeys.
///         The configuration for signers is provided via the `data` parameter in `validateSignatureWithData`,
///         making the validator stateless in its operation for each validation.
///
/// @dev Implements `ISessionValidator`. This module is intended to be a secure
///      and verifiable component, attestable via an EIP-7484 compliant module registry.
contract MultiKeySigner is ISessionValidator {
    using PasskeyHelper for *;
    using SignerEncode for *;

    // --- Errors ---

    /// @notice Reverted if the provided signature array's length does not match the signers array's length.
    error InvalidSignatureLength();
    /// @notice Reverted if an unsupported signer type is encountered during validation.
    error InvalidSignatureType();
    /// @notice Reverted if installation data is provided, as this module does not support it.
    error InstallationDataNotSupported();
    /// @notice Reverted if an unknown signer type is encountered during decoding.
    error UnknownSignerType();

    // --- External Functions ---

    /// @notice Hook called by the account when this module is installed.
    /// @dev As per ERC-7579, modules can use `data` for initialization. This stateless module does not
    ///      support initialization data via this function. If `data` is provided, the call will revert.
    ///      The actual signer configuration is passed dynamically during validation.
    /// @param data Arbitrary data passed by the account during installation. Must be empty for this module.
    function onInstall(bytes calldata data) external {
        if (data.length > 0) {
            revert InstallationDataNotSupported();
        }
    }

    /// @notice Hook called by the account when this module is uninstalled.
    /// @dev As per ERC-7579, modules can use `data` for cleanup or other actions upon uninstallation.
    ///      This stateless module currently has no specific state to clean up.
    function onUninstall(bytes calldata /* data */ ) external { }

    /// @notice Checks if this module conforms to a given module type ID, as per ERC-7579.
    /// @dev Returns true if the `id` matches the ERC-7579 Stateless Validator Module type ID.
    /// @param id The module type ID to check.
    /// @return isType True if this module is of the specified type, false otherwise.
    function isModuleType(uint256 id) external pure returns (bool) {
        return (id == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR);
    }

    /// @notice Checks if the contract supports a given interface ID.
    /// @dev Specifically checks for `ISessionValidator` interface support, often used in conjunction
    /// with ERC-7579 modules.
    /// @param sig The interface ID (bytes4) to check.
    /// @return supported True if the interface is supported, false otherwise.
    function supportsInterface(bytes4 sig) external view returns (bool) {
        return (sig == type(ISessionValidator).interfaceId);
    }

    function isInitialized(address /* smartAccount */ ) external view returns (bool) {
        return true; // This module is stateless and considered always initialized
    }

    /// @notice Validates a signature against a given user operation hash, using the module's configured signers.
    /// @dev This is a core function for an ERC-7579 Stateless Validator Module. It decodes the signers from `data`
    ///      and the corresponding signatures from `sig`, then validates each signature against the `userOpHash`.
    ///      Reverts with `InvalidSignatureLength` if `sig` and `signers` (decoded from `data`) lengths mismatch.
    ///      Reverts with `InvalidSignatureType` if an unsupported signer type is encountered.
    /// @param userOpHash The hash of the UserOperation to be validated.
    /// @param sig An ABI encoded byte array of signatures, one for each signer defined in `data`.
    /// @param data An ABI encoded byte array representing the `Signer[]` array configuration for this validation.
    /// @return validSig True if all signatures are valid, false otherwise.
    function validateSignatureWithData(
        bytes32 userOpHash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        view
        returns (bool validSig)
    {
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        Signer[] memory signers = data.decodeSigners();
        bytes[] memory sigs = abi.decode(sig, (bytes[]));

        uint256 length = signers.length;
        if (sigs.length != length) revert InvalidSignatureLength();

        for (uint256 i = 0; i < length; i++) {
            if (signers[i].signerType == SignerType.EOA) {
                address eoa = signers[i].decodeEOA();
                address recovered = ECDSA.recover(ethHash, sigs[i]);
                if (recovered != eoa) return false;
            } else if (signers[i].signerType == SignerType.PASSKEY) {
                WebAuthnValidatorData memory passkeyData = signers[i].decodePasskey();
                bool passkeyValid = passkeyData.verifyPasskey(userOpHash, sigs[i]);
                if (!passkeyValid) return false;
            } else {
                revert InvalidSignatureType();
            }
        }
        return true;
    }

    /// @notice Encodes an array of `Signer` structs into a byte array.
    /// @dev This helper function is used to prepare the `data` parameter for `validateSignatureWithData`.
    /// @param signers An array of `Signer` structs to encode.
    /// @return encoded The ABI encoded byte array of signers.
    function encodeSigners(Signer[] memory signers) external pure returns (bytes memory) {
        return signers.encodeSignersInternal();
    }
}
