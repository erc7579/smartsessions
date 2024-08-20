// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import "./EncodeLib.sol";

import "forge-std/console2.sol";

library MultichainHashLib {

    using EncodeLib for ISigner;
    using MultichainHashLib for bytes;

    error HashIndexOutOfBounds(uint256 index);
    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    function getAndVerifyDigest(EnableSessions memory enableData, uint256 nonce, SmartSessionMode mode) internal view returns (bytes32 digest) {
        bytes32 computedHash = enableData.sessionToEnable.isigner.digest(nonce, enableData.sessionToEnable, mode);
        
        (uint64 providedChainId, bytes32 providedHash) = enableData.hashesAndChainIds._parseHashAndChainIdByIndex(enableData.sessionIndex);

        if (providedChainId != block.chainid) {
            revert ChainIdMismatch(providedChainId);
        }

        if (providedHash != computedHash) {
            revert HashMismatch(providedHash, computedHash);
        }

        digest = keccak256(enableData.hashesAndChainIds);
    }

    function _parseHashAndChainIdByIndex(bytes memory hashesAndChainIds, uint8 index) internal pure returns (uint64 chainId, bytes32 hash) {
        if (index > hashesAndChainIds.length / 0x28) { //0x28 = 40 = 32bytes+8bytes
            revert HashIndexOutOfBounds(index);
        }
        assembly {
            let offset := add(hashesAndChainIds, add(0x20, mul(index, 0x28)))
            chainId := shr(192, mload(offset))
            hash := mload(add(offset, 0x08))
        }
    }
}
