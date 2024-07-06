// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import "forge-std/console2.sol";
import { LibZip } from "solady/utils/LibZip.sol";

library EncodeLib {
    using LibZip for bytes;
    using EncodeLib for *;

    // jjjjjj
    //     internal
    //     pure
    //     returns (SmartSessionMode mode, SignerId signerId, bytes calldata packedSig)
    // {
    //     mode = SmartSessionMode(uint8(bytes1(userOp.signature[:1])));
    //     signerId = SignerId.wrap(bytes32(userOp))
    //     packedSig = userOp.signature[1:];
    // }

    function packMode(
        bytes memory data,
        SmartSessionMode mode,
        SignerId signerId
    )
        internal
        pure
        returns (bytes memory packed)
    {
        packed = abi.encodePacked(mode, signerId, data);
    }

    function unpackMode(bytes calldata packed)
        internal
        pure
        returns (SmartSessionMode mode, SignerId signerId, bytes calldata signature)
    {
        mode = SmartSessionMode(uint8(bytes1(packed[:1])));
        signerId = SignerId.wrap(bytes32(packed[1:33]));
        signature = packed[33:];
    }

    function encodeUse(SignerId signerId, bytes memory packedSig) internal pure returns (bytes memory userOpSig) {
        bytes memory d = abi.encode(packedSig).flzCompress();
        userOpSig = d.packMode(SmartSessionMode.USE, signerId);
    }

    function decodeUse(bytes memory packedSig) internal pure returns (bytes memory signature) {
        (signature) = abi.decode(packedSig.flzDecompress(), (bytes));
    }

    function encodeEnable(
        SignerId signerId,
        bytes memory useSig,
        EnableSessions memory enableData
    )
        internal
        pure
        returns (bytes memory packedSig)
    {
        bytes memory data = abi.encode(enableData, useSig);
        data = data.flzCompress();
        packedSig = data.packMode(SmartSessionMode.UNSAFE_ENABLE, signerId);
    }

    function decodeEnable(bytes calldata packedSig)
        internal
        pure
        returns (EnableSessions memory enableData, bytes memory signature)
    {
        (enableData, signature) = abi.decode(packedSig.flzDecompress(), (EnableSessions, bytes));
    }

    // TODO: would be nice to use a custom EIP712 envelope here
    // TODO: add nonce for replay protection
    function digest(SignerId signerId, EnableSessions memory data) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                signerId,
                block.chainid,
                data.isigner,
                data.isignerInitData,
                data.userOpPolicies,
                data.erc1271Policies,
                data.actions
            )
        );
    }

    function decodeInstall(bytes calldata enableData) internal pure returns (InstallSessions[] memory sessions) {
        sessions = abi.decode(enableData, (InstallSessions[]));
    }
}
