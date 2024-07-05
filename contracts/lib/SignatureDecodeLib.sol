// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import "forge-std/console2.sol";

library SignatureDecodeLib {
    function decodeMode(PackedUserOperation calldata userOp)
        internal
        pure
        returns (SmartSessionMode mode, bytes calldata packedSig)
    {
        mode = SmartSessionMode(uint8(bytes1(userOp.signature[:1])));
        packedSig = userOp.signature[1:];
    }

    function encodeUse(SignerId signerId, bytes memory packedSig) internal pure returns (bytes memory userOpSig) {
        userOpSig = abi.encodePacked(SmartSessionMode.USE, signerId, packedSig);
    }

    function decodeUse(bytes calldata packedSig) internal pure returns (SignerId signerId, bytes calldata signature) {
        signerId = SignerId.wrap(bytes32(packedSig[0:32]));
        signature = packedSig[32:];
    }

    function decodePackedSigEnable(bytes calldata packedSig)
        internal
        pure
        returns (EnableSessions memory enableData, SignerId signerId, bytes calldata signature)
    {
        bytes memory tmp;
        signerId = SignerId.wrap(bytes32(packedSig[0:32]));
        // todo make this calldata
        (tmp, enableData) = abi.decode(packedSig[32:], (bytes, EnableSessions));
        // making sure singerId is still in the signature. this will be used by _enforcePolicies
        signature = packedSig[:tmp.length + 32];
    }

    function encodePackedSigEnable(
        SignerId signerId,
        bytes memory useSig,
        EnableSessions memory enableData
    )
        internal
        pure
        returns (bytes memory packedSig)
    {
        packedSig = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, signerId, abi.encode(useSig, enableData));
    }

    // TODO: would be nice to use a custom EIP712 envelope here
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

    function decodeEnable(bytes calldata enableData)
        internal
        pure
        returns (
            address[] memory userOpPolicies,
            address[] memory erc1271Policy,
            ActionId actionId,
            address[] memory actionPolicies
        )
    {
        (userOpPolicies, erc1271Policy, actionId, actionPolicies) =
            abi.decode(enableData, (address[], address[], ActionId, address[]));
    }

    function encodeEnable(
        address[] memory userOpPolicies,
        address[] memory erc1271Policy,
        ActionId actionId,
        address[] memory actionPolicies
    )
        internal
        pure
        returns (bytes memory enableData)
    {
        enableData = abi.encode(userOpPolicies, erc1271Policy, actionId, actionPolicies);
        enableData = abi.encodePacked(SmartSessionMode.UNSAFE_ENABLE, enableData);
    }

    function decodeInstall(bytes calldata enableData) internal pure returns (InstallSessions[] memory sessions) {
        sessions = abi.decode(enableData, (InstallSessions[]));
    }
}
