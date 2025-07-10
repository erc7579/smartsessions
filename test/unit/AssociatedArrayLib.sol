// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "contracts/utils/AssociatedArrayLib.sol";

contract AssociatedArrayLibTest is Test {
    using AssociatedArrayLib for AssociatedArrayLib.Bytes32Array;
    using AssociatedArrayLib for AssociatedArrayLib.AddressArray;
    using AssociatedArrayLib for AssociatedArrayLib.UintArray;

    // Test storage variables
    AssociatedArrayLib.Bytes32Array internal bytes32Array;
    AssociatedArrayLib.AddressArray internal addressArray;
    AssociatedArrayLib.UintArray internal uintArray;

    address constant TEST_ACCOUNT = address(0x1234);
    address constant TEST_ACCOUNT_2 = address(0x5678);

    function setUp() public { }

    // Test that arrays can exceed 128 elements
    function testPushBeyond128_Bytes32Array() public {
        // Push 150 elements
        for (uint256 i = 0; i < 150; i++) {
            bytes32Array.push(TEST_ACCOUNT, bytes32(i));
        }

        // Verify length
        assertEq(bytes32Array.length(TEST_ACCOUNT), 150);

        // Verify elements
        for (uint256 i = 0; i < 150; i++) {
            assertEq(bytes32Array.get(TEST_ACCOUNT, i), bytes32(i));
        }
    }

    function testPushBeyond128_AddressArray() public {
        // Push 200 elements
        for (uint256 i = 0; i < 200; i++) {
            addressArray.push(TEST_ACCOUNT, address(uint160(i + 1)));
        }

        // Verify length
        assertEq(addressArray.length(TEST_ACCOUNT), 200);

        // Verify elements
        for (uint256 i = 0; i < 200; i++) {
            assertEq(addressArray.get(TEST_ACCOUNT, i), address(uint160(i + 1)));
        }
    }

    function testPushBeyond128_UintArray() public {
        // Push 256 elements
        for (uint256 i = 0; i < 256; i++) {
            uintArray.push(TEST_ACCOUNT, i);
        }

        // Verify length
        assertEq(uintArray.length(TEST_ACCOUNT), 256);

        // Verify elements
        for (uint256 i = 0; i < 256; i++) {
            assertEq(uintArray.get(TEST_ACCOUNT, i), i);
        }
    }

    // Test add (unique elements) beyond 128
    function testAddBeyond128() public {
        // Add 150 unique elements
        for (uint256 i = 0; i < 150; i++) {
            bytes32Array.add(TEST_ACCOUNT, bytes32(i));
        }

        assertEq(bytes32Array.length(TEST_ACCOUNT), 150);

        // Try adding duplicates - length should not increase
        bytes32Array.add(TEST_ACCOUNT, bytes32(uint256(100)));
        bytes32Array.add(TEST_ACCOUNT, bytes32(uint256(100)));
        assertEq(bytes32Array.length(TEST_ACCOUNT), 150);
    }

    // Test set operation at high indices
    function testSetAtHighIndex() public {
        // Push 200 elements
        for (uint256 i = 0; i < 200; i++) {
            uintArray.push(TEST_ACCOUNT, i);
        }

        // Set value at index 199
        uintArray.set(TEST_ACCOUNT, 199, 9999);
        assertEq(uintArray.get(TEST_ACCOUNT, 199), 9999);

        // Set value at index 150
        uintArray.set(TEST_ACCOUNT, 150, 8888);
        assertEq(uintArray.get(TEST_ACCOUNT, 150), 8888);
    }

    // Test remove operation at high indices
    function testRemoveAtHighIndex() public {
        // Push 200 elements
        for (uint256 i = 0; i < 200; i++) {
            addressArray.push(TEST_ACCOUNT, address(uint160(i)));
        }

        // Remove element at index 150
        addressArray.remove(TEST_ACCOUNT, 150);
        assertEq(addressArray.length(TEST_ACCOUNT), 199);

        // The last element should have been moved to index 150
        assertEq(addressArray.get(TEST_ACCOUNT, 150), address(uint160(199)));
    }

    // Test pop operation with large arrays
    function testPopLargeArray() public {
        // Push 200 elements
        for (uint256 i = 0; i < 200; i++) {
            bytes32Array.push(TEST_ACCOUNT, bytes32(i));
        }

        // Pop 50 elements
        for (uint256 i = 0; i < 50; i++) {
            bytes32Array.pop(TEST_ACCOUNT);
        }

        assertEq(bytes32Array.length(TEST_ACCOUNT), 150);

        // Verify remaining elements
        for (uint256 i = 0; i < 150; i++) {
            assertEq(bytes32Array.get(TEST_ACCOUNT, i), bytes32(i));
        }
    }

    // Test getAll with large arrays
    function testGetAllLargeArray() public {
        uint256 size = 175;

        // Push elements
        for (uint256 i = 0; i < size; i++) {
            uintArray.push(TEST_ACCOUNT, i * 2);
        }

        uint256[] memory values = uintArray.getAll(TEST_ACCOUNT);
        assertEq(values.length, size);

        for (uint256 i = 0; i < size; i++) {
            assertEq(values[i], i * 2);
        }
    }

    // Test contains with large arrays
    function testContainsLargeArray() public {
        // Push 200 elements
        for (uint256 i = 0; i < 200; i++) {
            bytes32Array.push(TEST_ACCOUNT, bytes32(i));
        }

        // Test contains for various elements
        assertTrue(bytes32Array.contains(TEST_ACCOUNT, bytes32(0)));
        assertTrue(bytes32Array.contains(TEST_ACCOUNT, bytes32(uint256(50))));
        assertTrue(bytes32Array.contains(TEST_ACCOUNT, bytes32(uint256(199))));
        assertTrue(bytes32Array.contains(TEST_ACCOUNT, bytes32(uint256(150))));
        assertFalse(bytes32Array.contains(TEST_ACCOUNT, bytes32(uint256(200))));
        assertFalse(bytes32Array.contains(TEST_ACCOUNT, bytes32(uint256(300))));
    }

    // Test multiple accounts with large arrays
    function testMultipleAccountsLargeArrays() public {
        // Account 1: push 150 elements
        for (uint256 i = 0; i < 150; i++) {
            uintArray.push(TEST_ACCOUNT, i);
        }

        // Account 2: push 175 elements
        for (uint256 i = 0; i < 175; i++) {
            uintArray.push(TEST_ACCOUNT_2, i * 10);
        }

        // Verify lengths
        assertEq(uintArray.length(TEST_ACCOUNT), 150);
        assertEq(uintArray.length(TEST_ACCOUNT_2), 175);

        // Verify data isolation
        assertEq(uintArray.get(TEST_ACCOUNT, 100), 100);
        assertEq(uintArray.get(TEST_ACCOUNT_2, 100), 1000);
    }

    // Test edge case: exactly at old limit
    function testExactly128Elements() public {
        for (uint256 i = 0; i < 128; i++) {
            bytes32Array.push(TEST_ACCOUNT, bytes32(i));
        }

        assertEq(bytes32Array.length(TEST_ACCOUNT), 128);

        // Push one more to go beyond old limit
        bytes32Array.push(TEST_ACCOUNT, bytes32(uint256(128)));
        assertEq(bytes32Array.length(TEST_ACCOUNT), 129);
        assertEq(bytes32Array.get(TEST_ACCOUNT, 128), bytes32(uint256(128)));
    }

    // Test out of bounds access still reverts
    function testOutOfBoundsAccess() public {
        // Push 10 elements
        for (uint256 i = 0; i < 10; i++) {
            uintArray.push(TEST_ACCOUNT, i);
        }

        // Try to access out of bounds
        vm.expectRevert(abi.encodeWithSelector(AssociatedArrayLib.AssociatedArray_OutOfBounds.selector, 10));
        this.callGet(10);

        // Try to set out of bounds
        vm.expectRevert(abi.encodeWithSelector(AssociatedArrayLib.AssociatedArray_OutOfBounds.selector, 20));
        this.callSet(20, 9999);
    }

    // Fuzz test for arbitrary large sizes
    function testFuzz_LargeArraySizes(uint8 size) public {
        // Use uint8 to keep test time reasonable (max 255)
        vm.assume(size > 128); // Only test sizes beyond old limit

        for (uint256 i = 0; i < size; i++) {
            addressArray.push(TEST_ACCOUNT, address(uint160(i + 1000)));
        }

        assertEq(addressArray.length(TEST_ACCOUNT), size);

        // Verify random elements
        if (size > 0) {
            assertEq(addressArray.get(TEST_ACCOUNT, 0), address(uint160(1000)));
            assertEq(addressArray.get(TEST_ACCOUNT, size - 1), address(uint160(size + 999)));

            if (size > 128) {
                assertEq(addressArray.get(TEST_ACCOUNT, 128), address(uint160(1128)));
            }
        }
    }

    function callGet(uint256 index) public view returns (uint256) {
        return uintArray.get(TEST_ACCOUNT, index);
    }

    function callSet(uint256 index, uint256 value) public {
        uintArray.set(TEST_ACCOUNT, index, value);
    }
}
