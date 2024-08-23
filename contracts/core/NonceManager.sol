// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { PermissionId } from "../DataTypes.sol";

import { ISmartSession } from "../ISmartSession.sol";

abstract contract NonceManager is ISmartSession {
    mapping(PermissionId permissionId => mapping(address smartAccount => uint256 nonce)) internal $signerNonce;

    function getNonce(PermissionId permissionId, address account) external view returns (uint256) {
        return $signerNonce[permissionId][account];
    }

    function revokeEnableSignature(PermissionId permissionId) external {
        uint256 nonce = $signerNonce[permissionId][msg.sender]++;
        emit IterNonce(permissionId, msg.sender, nonce);
    }
}
