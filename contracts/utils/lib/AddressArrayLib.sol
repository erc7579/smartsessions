// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// credits @rhinestone @zeroknots
// https://github.com/rhinestonewtf/associatedBytesLib

uint256 constant MAX_ARRAY_LENGTH = 8;

struct AddressArray {
    address[MAX_ARRAY_LENGTH] data;
    uint256 nextIndex;
}

// WARNING!!! This library is
// most probably strongly underoptimized
// gas optimization required!

library AddressArrayLib {
    error IndexOutOfBounds(uint256 index, uint256 length);
    error ArrayFull();
    error NoSuchElement();

    using AddressArrayLib for *;

    function next(AddressArray storage self) internal view returns (uint256) {
        if (self.nextIndex >= MAX_ARRAY_LENGTH) revert ArrayFull();
        return self.nextIndex;
    }

    function lastUsedIndex(AddressArray storage self) internal view returns (uint256) {
        return self.nextIndex - 1;
    }

    function push(AddressArray storage self, address value) internal {
        self.data[next(self)] = value;
        self.nextIndex++;
    }

    function get(AddressArray storage self, uint256 index) internal view returns (address) {
        return self.data[index];
    }

    function length(AddressArray storage self) internal view returns (uint256) {
        return self.nextIndex;
    }

    // Not recommended for large arrays
    function removeIndex(AddressArray storage self, uint256 index) internal {
        if (index >= self.length()) revert IndexOutOfBounds(index, self.length());
        uint256 lastUsed = self.length() - 1;
        self.data[index] = self.data[lastUsed];
        delete self.data[lastUsed];
        self.nextIndex--;
    }

    function removeElement(AddressArray storage self, address value) internal returns (uint256 removedIndex) {
        for (uint256 i = 0; i < self.length(); i++) {
            if (self.data[i] == value) {
                uint256 lastUsed = self.length() - 1;
                self.data[i] = self.data[lastUsed];
                delete self.data[lastUsed];
                return i;
            }
        }
        revert NoSuchElement();
    }

    // Not recommended for large arrays
    function contains(AddressArray storage self, address value) internal view returns (bool) {
        for (uint256 i = 0; i < self.length(); i++) {
            if (self.data[i] == value) {
                return true;
            }
        }
        return false;
    }

    // Not recommended for large arrays
    function indexOf(AddressArray storage self, address value) internal view returns (uint256) {
        for (uint256 i = 0; i < self.length(); i++) {
            if (self.data[i] == value) {
                return i;
            }
        }
        revert NoSuchElement();
    }
}
