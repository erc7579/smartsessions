// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import "./EncodeLib.sol";
import "./HashLib.sol";

library MultichainHashLib {

    using EncodeLib for *;
    using HashLib for *;

    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    function getAndVerifyDigest(EnableSessions memory enableData, uint256 nonce, SmartSessionMode mode) internal view returns (bytes32 digest) {
        bytes32 computedHash = enableData.sessionToEnable.sessionDigest(mode, nonce);
        
        uint64 providedChainId = enableData.hashesAndChainIds[enableData.sessionIndex].chainId;
        bytes32 providedHash =  enableData.hashesAndChainIds[enableData.sessionIndex].sessionDigest;

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = enableData.hashesAndChainIds.multichainDigest();
    }
}
