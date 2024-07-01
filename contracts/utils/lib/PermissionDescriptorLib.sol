// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

type PermissionDescriptor is bytes4;

library PermissionDescriptorLib {
    function isSignerEnableMode(PermissionDescriptor descr) internal pure returns (bool) {
        return ((PermissionDescriptor.unwrap(descr)) >> 24) == 0x00000001;
    }

    function getUserOpPoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
        return uint256(uint32((PermissionDescriptor.unwrap(descr) & 0x00ff0000) >> 16));
    }

    function getActionPoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
        return uint256(uint32((PermissionDescriptor.unwrap(descr) & 0x0000ff00) >> 8));
    }

    function get1271PoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
        return uint256(uint32(PermissionDescriptor.unwrap(descr) & 0x000000ff));
    }
}
