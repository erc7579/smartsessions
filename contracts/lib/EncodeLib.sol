// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

library EncodeLib {
    using LibZip for bytes;
    using EncodeLib for *;

    error ChainIdAndHashesLengthMismatch(uint256 chainIdsLength, uint256 hashesLength);

    function packMode(
        bytes memory data,
        SmartSessionMode mode,
        PermissionId permissionId
    )
        internal
        pure
        returns (bytes memory packed)
    {
        packed = abi.encodePacked(mode, permissionId, data);
    }

    function unpackMode(
        bytes calldata packed
    )
        internal
        pure
        returns (SmartSessionMode mode, PermissionId permissionId, bytes calldata data)
    {
        mode = SmartSessionMode(uint8(bytes1(packed[:1])));
        permissionId = PermissionId.wrap(bytes32(packed[1:33]));
        data = packed[33:];
    }

    function encodeUse(PermissionId permissionId, bytes memory sig) internal pure returns (bytes memory userOpSig) {
        bytes memory d = abi.encode(sig).flzCompress();
        userOpSig = d.packMode(SmartSessionMode.USE, permissionId);
    }

    function decodeUse(bytes memory packedSig) internal pure returns (bytes memory signature) {
        (signature) = abi.decode(packedSig.flzDecompress(), (bytes));
    }

    function encodeEnable(
        PermissionId permissionId,
        bytes memory sig,
        EnableSession memory enableData
    )
        internal
        pure
        returns (bytes memory packedSig)
    {
        bytes memory data = abi.encode(enableData, sig);
        data = data.flzCompress();
        packedSig = data.packMode(SmartSessionMode.UNSAFE_ENABLE, permissionId);
    }

    function decodeEnable(
        bytes calldata packedSig
    )
        internal
        pure
        returns (EnableSession memory enableData, bytes memory signature)
    {
        (enableData, signature) = abi.decode(packedSig.flzDecompress(), (EnableSession, bytes));
    }

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

    // function encodeHashesAndChainIds(
    //     uint64[] memory chainIds,
    //     bytes32[] memory hashes
    // )
    //     internal
    //     pure
    //     returns (ChainDigest[] memory)
    // {
    //     uint256 length = chainIds.length;
    //     if (length != hashes.length) {
    //         revert ChainIdAndHashesLengthMismatch(length, hashes.length);
    //     }
    //
    //     ChainDigest[] memory hashesAndChainIds = new ChainDigest[](length);
    //     for (uint256 i; i < length; i++) {
    //         hashesAndChainIds[i] = ChainDigest({ chainId: chainIds[i], sessionDigest: hashes[i] });
    //     }
    //     return hashesAndChainIds;
    // }
}
