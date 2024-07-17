// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import "forge-std/Test.sol";
import "contracts/lib/EncodeLib.sol";
import "contracts/DataTypes.sol";

contract SigEncodeTest is Test {
    SignerId signerId;
    //
    // function setUp() public {
    //     signerId = SignerId.wrap(keccak256("1"));
    // }
    //
    // function test_encodeUseage(bytes memory sig) public {
    //     bytes memory encoded = EncodeLib.encodeUse(signerId, sig);
    //
    //     (SignerId _signerId, bytes memory _sig) = this.decodeUse(encoded);
    //
    //     assertEq(SignerId.unwrap(signerId), SignerId.unwrap(_signerId));
    //
    //     assertEq(keccak256(sig), keccak256(_sig));
    // }
    //
    // function test_encodeEnable(bytes memory sig, EnableSessions memory sessions) public {
    //     bytes memory encoded = EncodeLib.encodePackedSigEnable(signerId, sig, sessions);
    //     (EnableSessions memory _sessions, SignerId _signerId, bytes memory _sig) = this.decodeEnable(encoded);
    // }
    //
    // function decodeUse(bytes calldata foo) public returns (SignerId _signerId, bytes memory _sig) {
    //     (_signerId, _sig) = EncodeLib.decodeUse(foo[1:]);
    // }
    //
    // function decodeEnable(bytes calldata foo)
    //     public
    //     returns (EnableSessions memory _sessions, SignerId _signerId, bytes memory _sig)
    // {
    //     (_sessions, _signerId, _sig) = EncodeLib.decodePackedSigEnable(foo[1:]);
    // }
}
