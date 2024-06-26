// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { AddressArrayMap4337, ArrayMap4337Lib } from "contracts/utils/lib/ArrayMap4337Lib.sol";

import "forge-std/console2.sol";

contract ArrayMap4337LibTest is Test {
    using ArrayMap4337Lib for AddressArrayMap4337;

    mapping(uint256 => AddressArrayMap4337) addresses1;
    mapping(uint256 => AddressArrayMap4337) addresses2;

    function testAddressArrayMapNoStorageCollisionWithinMapping() public {
        AddressArrayMap4337 storage Addresses1ArrayMap1 = addresses1[1];
        AddressArrayMap4337 storage Addresses1ArrayMap2 = addresses1[2];
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xb0b)));
        assertFalse(Addresses1ArrayMap2.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap2.contains(address(1), address(0xb0b)));

        Addresses1ArrayMap1.push(address(1), address(0xa11ce));
        assertFalse(Addresses1ArrayMap2.contains(address(1), address(0xa11ce)));

        Addresses1ArrayMap2.push(address(1), address(0xb0b));
        
        assertTrue(Addresses1ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap2.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xb0b)));
        assertTrue(Addresses1ArrayMap2.contains(address(1), address(0xb0b)));
    }

    function testAddressArrayMapNoStorageCollisionBetweenMappings() public {
        AddressArrayMap4337 storage Addresses1ArrayMap1 = addresses1[1];
        AddressArrayMap4337 storage Addresses2ArrayMap1 = addresses2[1];
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xb0b)));
        assertFalse(Addresses2ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses2ArrayMap1.contains(address(1), address(0xb0b)));

        Addresses1ArrayMap1.push(address(1), address(0xa11ce));
        assertFalse(Addresses2ArrayMap1.contains(address(1), address(0xa11ce)));

        Addresses2ArrayMap1.push(address(1), address(0xb0b));
        
        assertTrue(Addresses1ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses2ArrayMap1.contains(address(1), address(0xa11ce)));
        assertFalse(Addresses1ArrayMap1.contains(address(1), address(0xb0b)));
        assertTrue(Addresses2ArrayMap1.contains(address(1), address(0xb0b)));
    }

}

