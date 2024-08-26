// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISessionValidator } from "../interfaces/ISessionValidator.sol";
import { IdLib } from "./IdLib.sol";

library SignerLib {
    using IdLib for *;
    using FlatBytesLib for *;

    error SignerNotFound(PermissionId permissionId, address account);
    error InvalidSessionKeySignature(
        PermissionId permissionId, ISessionValidator sessionValidator, address account, bytes32 userOpHash
    );

    function isValidISessionValidator(
        mapping(PermissionId => mapping(address => SignerConf)) storage $sessionValidators,
        bytes32 hash,
        address account,
        PermissionId permissionId,
        bytes memory signature
    )
        internal
        view
        returns (bool)
    {
        ISessionValidator sessionValidator = $sessionValidators[permissionId][account].sessionValidator;
        if (address(sessionValidator) == address(0)) revert SignerNotFound(permissionId, account);

        // check signature of ISessionValidator first.
        // policies only need to be processed if the signature is correct
        return sessionValidator.validateSignatureWithData({
            hash: hash,
            sig: signature,
            data: $sessionValidators[permissionId][account].config.load()
        });
    }
}
