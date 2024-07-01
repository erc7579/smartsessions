// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

contract Counter {
    uint256 public value;

    function incr() public payable {
        value += 1;
    }

    function decr() public payable {
        value -= 1;
    }
}
