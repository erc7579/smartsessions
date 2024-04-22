// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

type ValidAfter is uint48;
type ValidUntil is uint48;

struct SingleSignerPermission {
    ValidUntil validUntil;
    ValidAfter validAfter;
    address signatureValidationAlgorithm;
    bytes signer;
    // TODO: change it to address[] and bytes[] to be able to
    // stack policies for a permission
    // as of now it is enough to have a single policy for demo purposes
    address policy;
    bytes policyData;
}

interface IERC7579PermissionValidator {
    
    function getPermissionId(
        SingleSignerPermission calldata permission
    )
        external
        pure
        returns (bytes32);

}