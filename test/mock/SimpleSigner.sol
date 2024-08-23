// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { ISessionValidator } from "contracts/interfaces/ISessionValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

contract SimpleSigner is ISessionValidator {
    function supportsInterface(bytes4 interfaceID) external pure returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        view
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
