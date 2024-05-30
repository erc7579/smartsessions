// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// credits @rhinestone @zeroknots
// https://github.com/rhinestonewtf/associatedBytesLib

library AddressArrayLib {
    
    using AddressArrayLib for *;

    // 10*32 = 160
    // 320/20 = 16 addresses
    struct Data {
        bytes32[10] slot1;
    }

    struct AddressArray {
        uint256 totalLength;
        Data data;
    }



}