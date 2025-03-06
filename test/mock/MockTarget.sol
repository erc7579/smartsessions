// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

contract MockTarget {
    event FallbackEvent(bytes4 sig);

    uint256 public value;

    bytes32 public hash;

    function setValue(uint256 _value) public payable returns (uint256) {
        value = _value;
        return _value;
    }

    function increaseValue() public payable returns (uint256) {
        return ++value;
    }

    function getValue() public view returns (uint256) {
        return value;
    }

    function setHash(bytes32 _hash) public returns (bytes32) {
        hash = _hash;
        return _hash;
    }

    function executeFromExecutor(bytes32, bytes calldata callData) external returns (bytes[] memory returnData) {
        uint256 _value = uint256(bytes32(callData));
        value = _value;
        hash = keccak256(callData);
        returnData = new bytes[](1);
    }

    fallback() external {
        emit FallbackEvent(msg.sig);
    }
}
