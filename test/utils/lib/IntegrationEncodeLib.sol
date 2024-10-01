// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../../../contracts/DataTypes.sol";
import { ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";
import { SmartSessionModeLib } from "../../../contracts/lib/SmartSessionModeLib.sol";

library IntegrationEncodeLib {
    using SmartSessionModeLib for SmartSessionMode;

    error ChainIdAndHashesLengthMismatch(uint256 chainIdsLength, uint256 hashesLength);

    function encodeContext(
        uint192 nonceKey,
        ExecutionMode mode,
        PermissionId permissionId,
        EnableSession memory enableData
    )
        internal
        pure
        returns (bytes memory context)
    {
        context = abi.encodePacked(nonceKey, mode, permissionId, abi.encode(enableData));
    }

    function encodeHashesAndChainIds(
        uint64[] memory chainIds,
        bytes32[] memory hashes
    )
        internal
        pure
        returns (ChainDigest[] memory)
    {
        uint256 length = chainIds.length;
        if (length != hashes.length) {
            revert ChainIdAndHashesLengthMismatch(length, hashes.length);
        }

        ChainDigest[] memory hashesAndChainIds = new ChainDigest[](length);
        for (uint256 i; i < length; i++) {
            hashesAndChainIds[i] = ChainDigest({ chainId: chainIds[i], sessionDigest: hashes[i] });
        }
        return hashesAndChainIds;
    }
}
