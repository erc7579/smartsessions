// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { SignerId } from "../DataTypes.sol";

import { ISmartSession } from "../ISmartSession.sol";

abstract contract NonceManager is ISmartSession {
    mapping(SignerId signerId => mapping(address smartAccount => uint256 nonce)) internal $signerNonce;

    function getNonce(SignerId signerId, address account) external view returns (uint256) {
        return $signerNonce[signerId][account];
    }

    function revokeEnableSignature(SignerId signerId) external {
        uint256 nonce = $signerNonce[signerId][msg.sender]++;
        emit IterNonce(signerId, msg.sender, nonce);
    }
}
