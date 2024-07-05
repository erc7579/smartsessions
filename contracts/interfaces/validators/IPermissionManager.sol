// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

address constant NO_SIGNATURE_VALIDATION_REQUIRED = address(0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF);

interface ISmartSession {
    error ExecuteUserOpIsNotSupported();

    error PolicyAlreadyUsed(address userOpPolicy);

    error SignerIdNotEnabled(bytes32 signerId);
    error SignerIdAlreadyEnabled(bytes32 signerId);
}
