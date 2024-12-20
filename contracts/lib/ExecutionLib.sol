// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { CallType, ExecType, ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

/**
 * Helper Library for decoding Execution calldata
 * malloc for memory allocation is bad for gas. use this assembly instead
 */
library ExecutionLib {
    error ERC7579DecodingError();

    function decodeUserOpCallData(bytes calldata userOpCallData)
        internal
        pure
        returns (bytes calldata erc7579ExecutionCalldata)
    {
        assembly {
            if lt(userOpCallData.length, 68) { revert(0, 0) }
            let baseOffset := add(userOpCallData.offset, 0x24) //skip 4 bytes of selector and 32 bytes of execution mode
            let calldataLoadOffset := calldataload(baseOffset)
            // check for potential overflow in calldataLoadOffset
            if gt(calldataLoadOffset, 0xffffffffffffffff) { revert(0, 0) }
            erc7579ExecutionCalldata.offset := add(baseOffset, calldataLoadOffset)
            erc7579ExecutionCalldata.length := calldataload(sub(erc7579ExecutionCalldata.offset, 0x20))
            if gt(erc7579ExecutionCalldata.length, 0xffffffffffffffff) { revert(0, 0) }

            let calldataBound := add(userOpCallData.offset, userOpCallData.length)
            // revert if erc7579ExecutionCalldata starts after userOp finishes and if erc7579ExecutionCalldata ends
            // after userOp finishes
            if gt(erc7579ExecutionCalldata.offset, calldataBound) { revert(0, 0) }
            if gt(add(erc7579ExecutionCalldata.offset, erc7579ExecutionCalldata.length), calldataBound) { revert(0, 0) }
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

    /**
     * @notice Decode a batch of `Execution` pointers from a `bytes` calldata.
     * https://github.com/OpenZeppelin/openzeppelin-contracts/pull/5353
     */
    function decodeBatch(bytes calldata executionCalldata)
        internal
        pure
        returns (Execution[] calldata executionBatch)
    {
        unchecked {
            uint256 bufferLength = executionCalldata.length;

            // Check executionCalldata is not empty.
            if (bufferLength < 32) revert ERC7579DecodingError();

            // Get the offset of the array (pointer to the array length).
            uint256 arrayLengthPointer = uint256(bytes32(executionCalldata[0:32]));

            // The array length (at arrayLengthPointer) should be 32 bytes long. We check that this is within the
            // buffer bounds. Since we know bufferLength is at least 32, we can subtract with no overflow risk.
            if (arrayLengthPointer > bufferLength - 32) revert ERC7579DecodingError();

            // Get the array length. arrayLengthPointer + 32 is bounded by bufferLength so it does not overflow.
            uint256 arrayLength = uint256(bytes32(executionCalldata[arrayLengthPointer:arrayLengthPointer + 32]));

            // Check that the buffer is long enough to store the array elements as "offset pointer":
            // - each element of the array is an "offset pointer" to the data.
            // - each "offset pointer" (to an array element) takes 32 bytes.
            // - validity of the calldata at that location is checked when the array element is accessed, so we only
            //   need to check that the buffer is large enough to hold the pointers.
            //
            // Since we know bufferLength is at least arrayLengthPointer + 32, we can subtract with no overflow risk.
            // Solidity limits length of such arrays to 2**64-1, this guarantees `arrayLength * 32` does not overflow.
            if (arrayLength > type(uint64).max || bufferLength - arrayLengthPointer - 32 < arrayLength * 32) {
                revert ERC7579DecodingError();
            }

            assembly ("memory-safe") {
                executionBatch.offset := add(add(executionCalldata.offset, arrayLengthPointer), 32)
                executionBatch.length := arrayLength
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
