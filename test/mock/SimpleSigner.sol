// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { PackedUserOperation, SessionId, ISigner } from "contracts/interfaces/ISigner.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

contract SimpleSigner {
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        returns (bool validSig)
    {
        address owner = address(bytes20(data[0:20]));
        address recovered;
        recovered = ECDSA.recover(hash, sig);
        if (owner == recovered) {
            return true;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        recovered = ECDSA.recover(ethHash, sig);
        if (owner == recovered) {
            return true;
        }
        return false;
    }
}
