// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

// import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import "./passkey.sol";
import "contracts/interfaces/ISigner.sol";
import { SubLib } from "contracts/lib/SubLib.sol";
// import "./passkey.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

struct Config {
    address eoaSigner;
    WebAuthnValidatorData passkeySigner;
}

enum SignerType {
    EOA,
    PASSKEY
}

struct Signer {
    SignerType signerType;
    bytes data;
}

library SignerEncode {
    function decodeEOA(Signer memory signer) internal pure returns (address eoa) {
        eoa = address(bytes20(signer.data));
    }

    function decodePasskey(Signer memory signer) internal pure returns (WebAuthnValidatorData memory passkey) {
        passkey = abi.decode(signer.data, (WebAuthnValidatorData));
    }

    function decodeSigners(bytes memory data) internal pure returns (Signer[] memory signers) {
        signers = abi.decode(data, (Signer[]));
    }
}

contract MultiKeySigner {
    using PasskeyHelper for *;
    using SubLib for bytes;
    using SignerEncode for *;

    error InvalidPublicKey();

    error InvalidSignatureLength();
    error InvalidSignatureType();

    // can use sender as argument here as the method is view
    // so even external calls with arbitrary sender can not break things
    function checkSignature(
        SessionId signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (bytes4)
    {
        return 0xffffffff;
    }

    function onInstall(bytes calldata data) external {
        revert();
    }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }

    function supportsInterface(bytes4 sig) external view returns (bool) {
        return sig == type(ISigner).interfaceId;
    }

    function _deinitForAccount(address account, SessionId id) internal { }

    function checkUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256)
    {
        return 1;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external        
        returns (bool validSig)
    {
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
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
                WebAuthnValidatorData memory passkey = signers[i].decodePasskey();

                bool passkeyValid = passkey.verifyPasskey(ethHash, sigs[i]);
                if (!passkeyValid) return false;
            } else {
                revert InvalidSignatureType();
            }
        }

    }
}