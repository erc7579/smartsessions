// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/utils/EnumerableMap4337.sol";

contract EnumerableMapTest is Test {
    using EnumerableMap for EnumerableMap.Bytes32ToBytes32Map;
    using EnumerableMap for EnumerableMap.UintToUintMap;
    using EnumerableMap for EnumerableMap.UintToAddressMap;
    using EnumerableMap for EnumerableMap.AddressToUintMap;
    using EnumerableMap for EnumerableMap.Bytes32ToUintMap;

    EnumerableMap.Bytes32ToBytes32Map private bytes32ToBytes32Map;
    EnumerableMap.UintToUintMap private uintToUintMap;
    EnumerableMap.UintToAddressMap private uintToAddressMap;
    EnumerableMap.AddressToUintMap private addressToUintMap;
    EnumerableMap.Bytes32ToUintMap private bytes32ToUintMap;

    address private constant ACCOUNT = address(0x1234);

    function setUp() public {
        // Setup is empty as we're using fresh state for each test
    }

    function testBytes32ToBytes32Map() public {
        bytes32 key1 = bytes32(uint256(1));
        bytes32 value1 = bytes32(uint256(100));
        bytes32 key2 = bytes32(uint256(2));
        bytes32 value2 = bytes32(uint256(200));

        // Test set
        assertTrue(bytes32ToBytes32Map.set(ACCOUNT, key1, value1));
        assertFalse(bytes32ToBytes32Map.set(ACCOUNT, key1, value1)); // Duplicate set should return false

        // Test contains
        assertTrue(bytes32ToBytes32Map.contains(ACCOUNT, key1));
        assertFalse(bytes32ToBytes32Map.contains(ACCOUNT, key2));

        // Test length
        assertEq(bytes32ToBytes32Map.length(ACCOUNT), 1);

        // Test get
        assertEq(bytes32ToBytes32Map.get(ACCOUNT, key1), value1);

        // Test tryGet
        (bool success, bytes32 result) = bytes32ToBytes32Map.tryGet(ACCOUNT, key1);
        assertTrue(success);
        assertEq(result, value1);

        (success, result) = bytes32ToBytes32Map.tryGet(ACCOUNT, key2);
        assertFalse(success);
        assertEq(result, bytes32(0));

        // Test remove
        assertTrue(bytes32ToBytes32Map.remove(ACCOUNT, key1));
        assertFalse(bytes32ToBytes32Map.remove(ACCOUNT, key1)); // Removing non-existent key should return false

        // Test at and keys
        bytes32ToBytes32Map.set(ACCOUNT, key1, value1);
        bytes32ToBytes32Map.set(ACCOUNT, key2, value2);
        (bytes32 atKey, bytes32 atValue) = bytes32ToBytes32Map.at(ACCOUNT, 0);
        assertTrue(atKey == key1 || atKey == key2);
        assertTrue(atValue == value1 || atValue == value2);

        bytes32[] memory keys = bytes32ToBytes32Map.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue(keys[0] == key1 || keys[0] == key2);
        assertTrue(keys[1] == key1 || keys[1] == key2);
    }

    function testUintToUintMap() public {
        uint256 key1 = 1;
        uint256 value1 = 100;
        uint256 key2 = 2;
        uint256 value2 = 200;

        // Test set
        assertTrue(uintToUintMap.set(ACCOUNT, key1, value1));
        assertFalse(uintToUintMap.set(ACCOUNT, key1, value1)); // Duplicate set should return false

        // Test contains
        assertTrue(uintToUintMap.contains(ACCOUNT, key1));
        assertFalse(uintToUintMap.contains(ACCOUNT, key2));

        // Test length
        assertEq(uintToUintMap.length(ACCOUNT), 1);

        // Test get
        assertEq(uintToUintMap.get(ACCOUNT, key1), value1);

        // Test tryGet
        (bool success, uint256 result) = uintToUintMap.tryGet(ACCOUNT, key1);
        assertTrue(success);
        assertEq(result, value1);

        (success, result) = uintToUintMap.tryGet(ACCOUNT, key2);
        assertFalse(success);
        assertEq(result, 0);

        // Test remove
        assertTrue(uintToUintMap.remove(ACCOUNT, key1));
        assertFalse(uintToUintMap.remove(ACCOUNT, key1)); // Removing non-existent key should return false

        // Test at and keys
        uintToUintMap.set(ACCOUNT, key1, value1);
        uintToUintMap.set(ACCOUNT, key2, value2);
        (uint256 atKey, uint256 atValue) = uintToUintMap.at(ACCOUNT, 0);
        assertTrue(atKey == key1 || atKey == key2);
        assertTrue(atValue == value1 || atValue == value2);

        uint256[] memory keys = uintToUintMap.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue(keys[0] == key1 || keys[0] == key2);
        assertTrue(keys[1] == key1 || keys[1] == key2);
    }

    function testUintToAddressMap() public {
        uint256 key1 = 1;
        address value1 = address(0x5678);
        uint256 key2 = 2;
        address value2 = address(0x9ABC);

        // Test set
        assertTrue(uintToAddressMap.set(ACCOUNT, key1, value1));
        assertFalse(uintToAddressMap.set(ACCOUNT, key1, value1)); // Duplicate set should return false

        // Test contains
        assertTrue(uintToAddressMap.contains(ACCOUNT, key1));
        assertFalse(uintToAddressMap.contains(ACCOUNT, key2));

        // Test length
        assertEq(uintToAddressMap.length(ACCOUNT), 1);

        // Test get
        assertEq(uintToAddressMap.get(ACCOUNT, key1), value1);

        // Test tryGet
        (bool success, address result) = uintToAddressMap.tryGet(ACCOUNT, key1);
        assertTrue(success);
        assertEq(result, value1);

        (success, result) = uintToAddressMap.tryGet(ACCOUNT, key2);
        assertFalse(success);
        assertEq(result, address(0));

        // Test remove
        assertTrue(uintToAddressMap.remove(ACCOUNT, key1));
        assertFalse(uintToAddressMap.remove(ACCOUNT, key1)); // Removing non-existent key should return false

        // Test at and keys
        uintToAddressMap.set(ACCOUNT, key1, value1);
        uintToAddressMap.set(ACCOUNT, key2, value2);
        (uint256 atKey, address atValue) = uintToAddressMap.at(ACCOUNT, 0);
        assertTrue(atKey == key1 || atKey == key2);
        assertTrue(atValue == value1 || atValue == value2);

        uint256[] memory keys = uintToAddressMap.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue(keys[0] == key1 || keys[0] == key2);
        assertTrue(keys[1] == key1 || keys[1] == key2);
    }

    function testAddressToUintMap() public {
        address key1 = address(0x5678);
        uint256 value1 = 100;
        address key2 = address(0x9ABC);
        uint256 value2 = 200;

        // Test set
        assertTrue(addressToUintMap.set(ACCOUNT, key1, value1));
        assertFalse(addressToUintMap.set(ACCOUNT, key1, value1)); // Duplicate set should return false

        // Test contains
        assertTrue(addressToUintMap.contains(ACCOUNT, key1));
        assertFalse(addressToUintMap.contains(ACCOUNT, key2));

        // Test length
        assertEq(addressToUintMap.length(ACCOUNT), 1);

        // Test get
        assertEq(addressToUintMap.get(ACCOUNT, key1), value1);

        // Test tryGet
        (bool success, uint256 result) = addressToUintMap.tryGet(ACCOUNT, key1);
        assertTrue(success);
        assertEq(result, value1);

        (success, result) = addressToUintMap.tryGet(ACCOUNT, key2);
        assertFalse(success);
        assertEq(result, 0);

        // Test remove
        assertTrue(addressToUintMap.remove(ACCOUNT, key1));
        assertFalse(addressToUintMap.remove(ACCOUNT, key1)); // Removing non-existent key should return false

        // Test at and keys
        addressToUintMap.set(ACCOUNT, key1, value1);
        addressToUintMap.set(ACCOUNT, key2, value2);
        (address atKey, uint256 atValue) = addressToUintMap.at(ACCOUNT, 0);
        assertTrue(atKey == key1 || atKey == key2);
        assertTrue(atValue == value1 || atValue == value2);

        address[] memory keys = addressToUintMap.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue(keys[0] == key1 || keys[0] == key2);
        assertTrue(keys[1] == key1 || keys[1] == key2);
    }

    function testBytes32ToUintMap() public {
        bytes32 key1 = bytes32(uint256(1));
        uint256 value1 = 100;
        bytes32 key2 = bytes32(uint256(2));
        uint256 value2 = 200;

        // Test set
        assertTrue(bytes32ToUintMap.set(ACCOUNT, key1, value1));
        assertFalse(bytes32ToUintMap.set(ACCOUNT, key1, value1)); // Duplicate set should return false

        // Test contains
        assertTrue(bytes32ToUintMap.contains(ACCOUNT, key1));
        assertFalse(bytes32ToUintMap.contains(ACCOUNT, key2));

        // Test length
        assertEq(bytes32ToUintMap.length(ACCOUNT), 1);

        // Test get
        assertEq(bytes32ToUintMap.get(ACCOUNT, key1), value1);

        // Test tryGet
        (bool success, uint256 result) = bytes32ToUintMap.tryGet(ACCOUNT, key1);
        assertTrue(success);
        assertEq(result, value1);

        (success, result) = bytes32ToUintMap.tryGet(ACCOUNT, key2);
        assertFalse(success);
        assertEq(result, 0);

        // Test remove
        assertTrue(bytes32ToUintMap.remove(ACCOUNT, key1));
        assertFalse(bytes32ToUintMap.remove(ACCOUNT, key1)); // Removing non-existent key should return false

        // Test at and keys
        bytes32ToUintMap.set(ACCOUNT, key1, value1);
        bytes32ToUintMap.set(ACCOUNT, key2, value2);
        (bytes32 atKey, uint256 atValue) = bytes32ToUintMap.at(ACCOUNT, 0);
        assertTrue(atKey == key1 || atKey == key2);
        assertTrue(atValue == value1 || atValue == value2);

        bytes32[] memory keys = bytes32ToUintMap.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue(keys[0] == key1 || keys[0] == key2);
        assertTrue(keys[1] == key1 || keys[1] == key2);
    }

    function testFuzzBytes32ToBytes32Map(bytes32 key1, bytes32 value1, bytes32 key2, bytes32 value2) public {
        vm.assume(key1 != key2);

        assertTrue(bytes32ToBytes32Map.set(ACCOUNT, key1, value1));
        assertTrue(bytes32ToBytes32Map.set(ACCOUNT, key2, value2));

        assertEq(bytes32ToBytes32Map.length(ACCOUNT), 2);
        assertTrue(bytes32ToBytes32Map.contains(ACCOUNT, key1));
        assertTrue(bytes32ToBytes32Map.contains(ACCOUNT, key2));

        assertEq(bytes32ToBytes32Map.get(ACCOUNT, key1), value1);
        assertEq(bytes32ToBytes32Map.get(ACCOUNT, key2), value2);

        bytes32[] memory keys = bytes32ToBytes32Map.keys(ACCOUNT);
        assertEq(keys.length, 2);
        assertTrue((keys[0] == key1 && keys[1] == key2) || (keys[0] == key2 && keys[1] == key1));

        assertTrue(bytes32ToBytes32Map.remove(ACCOUNT, key1));
        assertFalse(bytes32ToBytes32Map.contains(ACCOUNT, key1));
        assertEq(bytes32ToBytes32Map.length(ACCOUNT), 1);
    }
}
