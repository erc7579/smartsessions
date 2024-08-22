// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import "./EncodeLib.sol";
import "./HashLib.sol";

library MultichainHashLib {
    using EncodeLib for *;
    using HashLib for Session;

    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    function getAndVerifyDigest(
        EnableSessions memory enableData,
        uint256 nonce,
        SmartSessionMode mode
    )
        internal
        view
        returns (bytes32 digest)
    {
        bytes32 computedHash = enableData.sessionToEnable.digest(mode, nonce);

        (uint64 providedChainId, bytes32 providedHash) =
            enableData.hashesAndChainIds.parseHashAndChainIdByIndex(enableData.sessionIndex);

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = keccak256(enableData.hashesAndChainIds);
    }
}
