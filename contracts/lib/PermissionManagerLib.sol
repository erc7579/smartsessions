import "../DataTypes.sol";

library PermissionManagerLib {
    function decodeSig(bytes calldata signature)
        internal
        pure
        returns (
            uint8 permissionIndex,
            bytes calldata permissionEnableData,
            bytes calldata permissionEnableDataSignature,
            bytes calldata permissionData,
            bytes calldata cleanSig
        )
    {
        permissionIndex = uint8(signature[1]);

        assembly {
            let baseOffset := add(signature.offset, 0x02)
            let offset := baseOffset

            // get permissionEnableData
            let dataPointer := add(baseOffset, calldataload(offset))
            permissionEnableData.offset := add(0x20, dataPointer)
            permissionEnableData.length := calldataload(dataPointer)

            // get permissionEnableDataSignature
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            permissionEnableDataSignature.offset := add(0x20, dataPointer)
            permissionEnableDataSignature.length := calldataload(dataPointer)

            // get permissionData
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            permissionData.offset := add(0x20, dataPointer)
            permissionData.length := calldataload(dataPointer)

            // get cleanSig
            offset := add(offset, 0x20)
            dataPointer := add(baseOffset, calldataload(offset))
            cleanSig.offset := add(0x20, dataPointer)
            cleanSig.length := calldataload(dataPointer)
        }
    }

    function parsePermissionEnable(
        bytes calldata permissionEnableData,
        uint8 permissionIndex
    )
        internal
        pure
        returns (uint64 permissionChainId, bytes32 permissionDigest)
    {
        assembly {
            let baseOffset := permissionEnableData.offset
            // 40 = chainId (8bytes) + digest (32 bytes)
            let offset := add(baseOffset, mul(40, permissionIndex))
            permissionChainId := shr(192, calldataload(offset))
            permissionDigest := calldataload(add(offset, 8))
        }
    }
}
