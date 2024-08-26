// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "contracts/lib/EncodeLib.sol";
import "contracts/DataTypes.sol";

contract SigEncodeTest is Test {
    PermissionId permissionId;
    //
    // function setUp() public {
    //     permissionId = PermissionId.wrap(keccak256("1"));
    // }
    //
    // function test_encodeUseage(bytes memory sig) public {
    //     bytes memory encoded = EncodeLib.encodeUse(permissionId, sig);
    //
    //     (PermissionId _permissionId, bytes memory _sig) = this.decodeUse(encoded);
    //
    //     assertEq(PermissionId.unwrap(permissionId), PermissionId.unwrap(_permissionId));
    //
    //     assertEq(keccak256(sig), keccak256(_sig));
    // }
    //
    // function test_encodeEnable(bytes memory sig, EnableSession memory sessions) public {
    //     bytes memory encoded = EncodeLib.encodePackedSigEnable(permissionId, sig, sessions);
    //     (EnableSession memory _sessions, PermissionId _permissionId, bytes memory _sig) = this.decodeEnable(encoded);
    // }
    //
    // function decodeUse(bytes calldata foo) public returns (PermissionId _permissionId, bytes memory _sig) {
    //     (_permissionId, _sig) = EncodeLib.decodeUse(foo[1:]);
    // }
    //
    // function decodeEnable(bytes calldata foo)
    //     public
    //     returns (EnableSession memory _sessions, PermissionId _permissionId, bytes memory _sig)
    // {
    //     (_sessions, _permissionId, _sig) = EncodeLib.decodePackedSigEnable(foo[1:]);
    // }
}
