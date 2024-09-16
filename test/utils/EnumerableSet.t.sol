// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/utils/EnumerableSet4337.sol";

contract EnumerableSetTest is Test {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.UintSet;

    EnumerableSet.Bytes32Set private bytes32Set;
    EnumerableSet.AddressSet private addressSet;
    EnumerableSet.UintSet private uintSet;

    address private constant ACCOUNT = address(0x1234);

    function setUp() public {
        // Setup is empty as we're using fresh state for each test
    }

    function testBytes32Set() public {
        bytes32 value1 = bytes32(uint256(1));
        bytes32 value2 = bytes32(uint256(2));

        // Test add
        assertTrue(bytes32Set.add(ACCOUNT, value1));
        assertFalse(bytes32Set.add(ACCOUNT, value1)); // Duplicate add should return false

        // Test contains
        assertTrue(bytes32Set.contains(ACCOUNT, value1));
        assertFalse(bytes32Set.contains(ACCOUNT, value2));

        // Test length
        assertEq(bytes32Set.length(ACCOUNT), 1);

        // Test at
        assertEq(bytes32Set.at(ACCOUNT, 0), value1);

        // Test remove
        assertTrue(bytes32Set.remove(ACCOUNT, value1));
        assertFalse(bytes32Set.remove(ACCOUNT, value1)); // Removing non-existent element should return false

        // Test values
        bytes32Set.add(ACCOUNT, value1);
        bytes32Set.add(ACCOUNT, value2);
        bytes32[] memory values = bytes32Set.values(ACCOUNT);
        assertEq(values.length, 2);
        assertTrue(values[0] == value1 || values[1] == value1);
        assertTrue(values[0] == value2 || values[1] == value2);
    }

    function testBytes32RemoveAllBug() public {
        bytes32Set.add(ACCOUNT, bytes32(uint256(1)));
        bytes32Set.add(ACCOUNT, bytes32(uint256(2)));

        assertEq(bytes32Set.length(ACCOUNT), 2, "length");

        bytes32Set.removeAll(ACCOUNT);

        // This is a bug, the length would be expected to be 0
        assertEq(bytes32Set.length(ACCOUNT), 0, "length should be 0");
    }

    function testAddressSet() public {
        address value1 = address(0x5678);
        address value2 = address(0x9ABC);

        // Test add
        assertTrue(addressSet.add(ACCOUNT, value1));
        assertFalse(addressSet.add(ACCOUNT, value1)); // Duplicate add should return false

        // Test contains
        assertTrue(addressSet.contains(ACCOUNT, value1));
        assertFalse(addressSet.contains(ACCOUNT, value2));

        // Test length
        assertEq(addressSet.length(ACCOUNT), 1);

        // Test at
        assertEq(addressSet.at(ACCOUNT, 0), value1);

        // Test remove
        assertTrue(addressSet.remove(ACCOUNT, value1));
        assertFalse(addressSet.remove(ACCOUNT, value1)); // Removing non-existent element should return false

        // Test values
        addressSet.add(ACCOUNT, value1);
        addressSet.add(ACCOUNT, value2);
        address[] memory values = addressSet.values(ACCOUNT);
        assertEq(values.length, 2);
        assertTrue(values[0] == value1 || values[1] == value1);
        assertTrue(values[0] == value2 || values[1] == value2);
    }

    function testUintSet() public {
        uint256 value1 = 1;
        uint256 value2 = 2;

        // Test add
        assertTrue(uintSet.add(ACCOUNT, value1));
        assertFalse(uintSet.add(ACCOUNT, value1)); // Duplicate add should return false

        // Test contains
        assertTrue(uintSet.contains(ACCOUNT, value1));
        assertFalse(uintSet.contains(ACCOUNT, value2));

        // Test length
        assertEq(uintSet.length(ACCOUNT), 1);

        // Test at
        assertEq(uintSet.at(ACCOUNT, 0), value1);

        // Test remove
        assertTrue(uintSet.remove(ACCOUNT, value1));
        assertFalse(uintSet.remove(ACCOUNT, value1)); // Removing non-existent element should return false

        // Test values
        uintSet.add(ACCOUNT, value1);
        uintSet.add(ACCOUNT, value2);
        uint256[] memory values = uintSet.values(ACCOUNT);
        assertEq(values.length, 2);
        assertTrue(values[0] == value1 || values[1] == value1);
        assertTrue(values[0] == value2 || values[1] == value2);
    }

    function testFuzzBytes32Set(bytes32[] memory testValues) public {
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < testValues.length; i++) {
            if (bytes32Set.add(ACCOUNT, testValues[i])) {
                uniqueCount++;
            }
        }

        assertEq(bytes32Set.length(ACCOUNT), uniqueCount);

        for (uint256 i = 0; i < testValues.length; i++) {
            assertTrue(bytes32Set.contains(ACCOUNT, testValues[i]));
        }

        bytes32[] memory values = bytes32Set.values(ACCOUNT);
        assertEq(values.length, uniqueCount);

        for (uint256 i = 0; i < uniqueCount; i++) {
            assertTrue(bytes32Set.remove(ACCOUNT, values[i]));
        }

        assertEq(bytes32Set.length(ACCOUNT), 0);
    }

    function testFuzzAddressSet(address[] memory testValues) public {
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < testValues.length; i++) {
            if (addressSet.add(ACCOUNT, testValues[i])) {
                uniqueCount++;
            }
        }

        assertEq(addressSet.length(ACCOUNT), uniqueCount);

        for (uint256 i = 0; i < testValues.length; i++) {
            assertTrue(addressSet.contains(ACCOUNT, testValues[i]));
        }

        address[] memory values = addressSet.values(ACCOUNT);
        assertEq(values.length, uniqueCount);

        for (uint256 i = 0; i < uniqueCount; i++) {
            assertTrue(addressSet.remove(ACCOUNT, values[i]));
        }

        assertEq(addressSet.length(ACCOUNT), 0);
    }

    function testFuzzUintSet(uint256[] memory testValues) public {
        uint256 uniqueCount = 0;
        for (uint256 i = 0; i < testValues.length; i++) {
            if (uintSet.add(ACCOUNT, testValues[i])) {
                uniqueCount++;
            }
        }

        assertEq(uintSet.length(ACCOUNT), uniqueCount);

        for (uint256 i = 0; i < testValues.length; i++) {
            assertTrue(uintSet.contains(ACCOUNT, testValues[i]));
        }

        uint256[] memory values = uintSet.values(ACCOUNT);
        assertEq(values.length, uniqueCount);

        for (uint256 i = 0; i < uniqueCount; i++) {
            assertTrue(uintSet.remove(ACCOUNT, values[i]));
        }

        assertEq(uintSet.length(ACCOUNT), 0);
    }
}
