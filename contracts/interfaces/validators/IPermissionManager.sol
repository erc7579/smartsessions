// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

interface IPermissionManager {

    type SignerId is bytes32;
    type ActionId is bytes32;

    error ExecuteUserOpIsNotSupported();

    error UserOpPolicyAlreadyUsed(SignerId signerId, address smartAccount, address userOpPolicy);

}
