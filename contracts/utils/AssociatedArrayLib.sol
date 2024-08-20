// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library AssociatedArrayLib {
    using AssociatedArrayLib for *;

    error AssociatedArray_OutOfBounds(uint256 index);

    struct Array {
        uint256 _spacer;
    }

    function _length(Array storage s, address account) private view returns (uint256 __length) {
        assembly {
            mstore(0x00, account)
            mstore(0x20, s.slot)
            __length := sload(keccak256(0x00, 0x40))
        }
    }

    function _get(Array storage s, address account, uint256 index) private view returns (bytes32 value) {
        assembly {
            mstore(0x00, account)
            mstore(0x20, s.slot)
            value := sload(add(keccak256(0x00, 0x40), mul(0x20, add(index, 1))))
        }
    }

    function _getAll(Array storage s, address account) private view returns (bytes32[] memory values) {
        uint256 __length = _length(s, account);
        values = new bytes32[](__length);
        for (uint256 i; i < __length; i++) {
            values[i] = _get(s, account, i);
        }
    }

    function _set(Array storage s, address account, uint256 index, bytes32 value) private {
        if (index >= _length(s, account)) revert AssociatedArray_OutOfBounds(index);
        assembly {
            mstore(0x00, account)
            mstore(0x20, s.slot)
            sstore(add(keccak256(0x00, 0x40), mul(0x20, add(index, 1))), value)
        }
    }

    function _push(Array storage s, address account, bytes32 value) private {
        assembly {
            mstore(0x00, account) // store a
            mstore(0x20, s.slot) //store x
            let slot := keccak256(0x00, 0x40)
            // load length (stored @ slot), add 1 to it => index.
            // mul index by 0x20 and add it to orig slot to get the next free slot
            let index := add(sload(slot), 1)
            sstore(add(slot, mul(0x20, index)), value)
            sstore(slot, index) //increment length by 1
        }
    }

    function _pop(Array storage s, address account) private {
        uint256 __length = _length(s, account);
        if (__length == 0) return;
        _set(s, account, __length - 1, 0);
        assembly {
            mstore(0x00, account)
            mstore(0x20, s.slot)
            sstore(keccak256(0x00, 0x40), sub(__length, 1))
        }
    }

    function _remove(Array storage s, address account, uint256 index) private {
        uint256 __length = _length(s, account);
        if (index >= __length) revert AssociatedArray_OutOfBounds(index);
        _set(s, account, index, _get(s, account, __length - 1));
        assembly {
            mstore(0x00, account)
            mstore(0x20, s.slot)
            sstore(keccak256(0x00, 0x40), sub(__length, 1))
        }
    }

    struct Bytes32Array {
        Array _inner;
    }

    function length(Bytes32Array storage s, address account) internal view returns (uint256) {
        return _length(s._inner, account);
    }

    function get(Bytes32Array storage s, address account, uint256 index) internal view returns (bytes32) {
        return _get(s._inner, account, index);
    }

    function getAll(Bytes32Array storage s, address account) internal view returns (bytes32[] memory) {
        return _getAll(s._inner, account);
    }

    function set(Bytes32Array storage s, address account, uint256 index, bytes32 value) internal {
        _set(s._inner, account, index, value);
    }

    function push(Bytes32Array storage s, address account, bytes32 value) internal {
        _push(s._inner, account, value);
    }

    function pop(Bytes32Array storage s, address account) internal {
        _pop(s._inner, account);
    }

    function remove(Bytes32Array storage s, address account, uint256 index) internal {
        _remove(s._inner, account, index);
    }

    struct AddressArray {
        Array _inner;
    }

    function length(AddressArray storage s, address account) internal view returns (uint256) {
        return _length(s._inner, account);
    }

    function get(AddressArray storage s, address account, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_get(s._inner, account, index))));
    }

    function getAll(AddressArray storage s, address account) internal view returns (address[] memory) {
        bytes32[] memory bytes32Array = _getAll(s._inner, account);
        address[] memory addressArray;

        /// @solidity memory-safe-assembly
        assembly {
            addressArray := bytes32Array
        }
        return addressArray;
    }

    function set(AddressArray storage s, address account, uint256 index, address value) internal {
        _set(s._inner, account, index, bytes32(uint256(uint160(value))));
    }

    function push(AddressArray storage s, address account, address value) internal {
        _push(s._inner, account, bytes32(uint256(uint160(value))));
    }

    function pop(AddressArray storage s, address account) internal {
        _pop(s._inner, account);
    }

    function remove(AddressArray storage s, address account, uint256 index) internal {
        _remove(s._inner, account, index);
    }

    struct UintArray {
        Array _inner;
    }

    function length(UintArray storage s, address account) internal view returns (uint256) {
        return _length(s._inner, account);
    }

    function get(UintArray storage s, address account, uint256 index) internal view returns (uint256) {
        return uint256(_get(s._inner, account, index));
    }

    function getAll(UintArray storage s, address account) internal view returns (uint256[] memory) {
        bytes32[] memory bytes32Array = _getAll(s._inner, account);
        uint256[] memory uintArray;

        /// @solidity memory-safe-assembly
        assembly {
            uintArray := bytes32Array
        }
        return uintArray;
    }

    function set(UintArray storage s, address account, uint256 index, uint256 value) internal {
        _set(s._inner, account, index, bytes32(value));
    }

    function push(UintArray storage s, address account, uint256 value) internal {
        _push(s._inner, account, bytes32(value));
    }

    function pop(UintArray storage s, address account) internal {
        _pop(s._inner, account);
    }

    function remove(UintArray storage s, address account, uint256 index) internal {
        _remove(s._inner, account, index);
    }
}
