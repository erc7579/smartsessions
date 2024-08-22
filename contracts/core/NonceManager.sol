// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { SignerId } from "../DataTypes.sol";

abstract contract NonceManager {
    event IterNonce(SignerId signerId, address account, uint256 newValue);

    mapping(SignerId signerId => mapping(address smartAccount => uint256 nonce)) internal $signerNonce;

    function getNonce(SignerId signerId, address account) external view returns (uint256) {
        return $signerNonce[signerId][account];
    }

    function revokeEnableSignature(SignerId signerId) external {
        uint256 nonce = $signerNonce[signerId][msg.sender]++;
        emit IterNonce(signerId, msg.sender, nonce);
    }
}
