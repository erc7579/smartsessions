// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

interface ISignerValidator {
    
    function checkSignature(bytes32 signerId, address sender, bytes32 hash, bytes calldata sig)
        external
        view
        returns (bytes4);

}
