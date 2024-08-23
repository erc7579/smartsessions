// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { WebAuthn } from "./WebAuthn.sol";

struct WebAuthnValidatorData {
    uint256 pubKeyX;
    uint256 pubKeyY;
}

library PasskeyHelper {
    uint256 constant CHALLENGE_LOCATION = 23;
    /**
     * @notice Verify a signature.
     */

    function verifyPasskey(
        WebAuthnValidatorData memory webAuthnData,
        bytes32 hash,
        bytes memory signature
    )
        internal
        view
        returns (bool isValid)
    {
        // decode the signature
        (
            bytes memory authenticatorData,
            string memory clientDataJSON,
            uint256 responseTypeLocation,
            uint256 r,
            uint256 s,
            bool usePrecompiled
        ) = abi.decode(signature, (bytes, string, uint256, uint256, uint256, bool));

        // handle stack too deep
        WebAuthnValidatorData memory ww = webAuthnData;

        // verify the signature using the signature and the public key
        isValid = WebAuthn.verifySignature(
            abi.encodePacked(hash),
            authenticatorData,
            true,
            clientDataJSON,
            CHALLENGE_LOCATION,
            responseTypeLocation,
            r,
            s,
            ww.pubKeyX,
            ww.pubKeyY,
            usePrecompiled
        );
    }
}
