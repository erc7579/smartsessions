// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

type PermissionDescriptor is bytes4;

library NonceMixinLib {
    function mixinNonce(bytes32 hash, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hash, nonce));
    }
}
