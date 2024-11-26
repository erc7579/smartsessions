// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { CallType, ExecType, ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

/**
 * Helper Library for decoding Execution calldata
 * malloc for memory allocation is bad for gas. use this assembly instead
 */
library ExecutionLib {
    function decodeUserOpCallData(bytes calldata userOpCallData)
        internal
        pure
        returns (bytes calldata erc7579ExecutionCalldata)
    {
        //bytes calldata data  = userOpCallData;
        assembly {
            let baseOffset := add(userOpCallData.offset, 0x24) //skip 4 bytes of selector and 32 bytes of execution mode
            let calldataLoadOffset := calldataload(baseOffset)
            // check for potential overflow in calldataLoadOffset
            if gt(calldataLoadOffset, 0xffffffffffffffff) { revert(0, 0) }
            erc7579ExecutionCalldata.offset := add(baseOffset, calldataLoadOffset)
            erc7579ExecutionCalldata.length := calldataload(sub(erc7579ExecutionCalldata.offset, 0x20))
            // TODO: check is sufficient
            // forgefmt: disable-next-item
            if lt(add(erc7579ExecutionCalldata.offset, erc7579ExecutionCalldata.length), 
                  erc7579ExecutionCalldata.offset) { revert(0, 0) }
        }
    }

    function get7579ExecutionMode(bytes calldata userOpCallData) internal pure returns (ExecutionMode mode) {
        mode = ExecutionMode.wrap(bytes32(userOpCallData[4:36]));
    }

    function get7579ExecutionTypes(bytes calldata userOpCallData)
        internal
        pure
        returns (CallType callType, ExecType execType)
    {
        ExecutionMode mode = ExecutionMode.wrap(bytes32(userOpCallData[4:36]));

        // solhint-disable-next-line no-inline-assembly
        assembly {
            callType := mode
            execType := shl(8, mode)
        }
    }

    function _decodeBatch(bytes calldata executionData) internal pure returns (Execution[] calldata pointers) {
        /*
         * Batch Call Calldata Layout
         * Offset (in bytes)    | Length (in bytes) | Contents
         * 0x0                  | 0x4               | bytes4 function selector
        *  0x4                  | -                 |
        abi.encode(IERC7579Execution.Execution[])
         */
        // solhint-disable-next-line no-inline-assembly
        /// @solidity memory-safe-assembly
        assembly {
            let u := calldataload(executionData.offset)
            if or(shr(64, u), gt(0x20, executionData.length)) {
                mstore(0x00, 0xba597e7e) // `DecodingError()`.
                revert(0x1c, 0x04)
            }
            pointers.offset := add(add(executionData.offset, u), 0x20)
            pointers.length := calldataload(add(executionData.offset, u))
            if pointers.length {
                let e := sub(add(executionData.offset, executionData.length), 0x20)
                // Perform bounds checks on the decoded `pointers`.
                // Does an out-of-gas revert.
                for { let i := pointers.length } 1 { } {
                    i := sub(i, 1)
                    let p := calldataload(add(pointers.offset, shl(5, i)))
                    let c := add(pointers.offset, p)
                    let q := calldataload(add(c, 0x40))
                    let o := add(c, q)
                    // forgefmt: disable-next-item
                    if or(shr(64, or(calldataload(o), or(p, q))),
                        or(gt(add(c, 0x40), e), gt(add(o, calldataload(o)), e))) {
                        mstore(0x00, 0xba597e7e) // `DecodingError()`.
                        revert(0x1c, 0x04)
                    }
                    if iszero(i) { break }
                }
            }
        }
    }

    function decodeBatch(bytes calldata executionData) internal pure returns (Execution[] calldata pointers) {
        /// @solidity memory-safe-assembly
        assembly {
            let u := calldataload(executionData.offset)
            if or(shr(64, u), gt(0x20, executionData.length)) {
                mstore(0x00, 0xba597e7e) // `DecodingError()`.
                revert(0x1c, 0x04)
            }
            pointers.offset := add(add(executionData.offset, u), 0x20)
            pointers.length := calldataload(add(executionData.offset, u))
            if pointers.length {
                let e := sub(add(executionData.offset, executionData.length), 0x20)
                // Perform bounds checks on the decoded `pointers`.
                // Does an out-of-gas revert.
                for { let i := pointers.length } 1 { } {
                    i := sub(i, 1)
                    let p := calldataload(add(pointers.offset, shl(5, i)))
                    let c := add(pointers.offset, p)
                    let q := calldataload(add(c, 0x40))
                    let o := add(c, q)
                    // forgefmt: disable-next-item
                    if or(shr(64, or(calldataload(o), or(p, q))),
                        or(gt(add(c, 0x40), e), gt(add(o, calldataload(o)), e))) {
                        mstore(0x00, 0xba597e7e) // `DecodingError()`.
                        revert(0x1c, 0x04)
                    }
                    if iszero(i) { break }
                }
            }
        }
    }

    function encodeBatch(Execution[] memory executions) internal pure returns (bytes memory callData) {
        callData = abi.encode(executions);
    }

    function decodeSingle(bytes calldata executionCalldata)
        internal
        pure
        returns (address target, uint256 value, bytes calldata callData)
    {
        target = address(bytes20(executionCalldata[0:20]));
        value = uint256(bytes32(executionCalldata[20:52]));
        callData = executionCalldata[52:];
    }

    function encodeSingle(
        address target,
        uint256 value,
        bytes memory callData
    )
        internal
        pure
        returns (bytes memory userOpCalldata)
    {
        userOpCalldata = abi.encodePacked(target, value, callData);
    }
}
