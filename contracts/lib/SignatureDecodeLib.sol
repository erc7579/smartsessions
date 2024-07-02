import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

library SignatureDecodeLib {
    function decodeMode(PackedUserOperation calldata userOp)
        internal
        pure
        returns (PermissionManagerMode mode, bytes calldata packedSig)
    {
        mode = PermissionManagerMode(uint8(bytes1(userOp.signature[:1])));
        packedSig = userOp.signature[1:];
    }

    function decodeUse(bytes calldata packedSig) internal pure returns (SignerId signerId, bytes calldata signature) {
        signerId = SignerId.wrap(bytes32(packedSig[1:33]));
        signature = packedSig[33:];
    }

    function decodeEnable(bytes calldata packedSig)
        internal
        pure
        returns (
            uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata signature
        )
    {
        // TODO: these are just placeholders

        permissionIndex = uint8(packedSig[1]);
        permissionEnableData = packedSig[2:34];
        permissionEnableDataSignature = packedSig[34:66];
        permissionData = packedSig[66:98];
        signature = packedSig[98:];
    }
}
