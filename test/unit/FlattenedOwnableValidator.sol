// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity <0.9.0 >=0.6.2 >=0.7.5 >=0.8.0 >=0.8.23 ^0.8.0 ^0.8.19 ^0.8.20 ^0.8.23 ^0.8.25 ^0.8.4;

// node_modules/solady/src/utils/ECDSA.sol

/// @notice Gas optimized ECDSA wrapper.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/ECDSA.sol)
/// @author Modified from Solmate (https://github.com/transmissions11/solmate/blob/main/src/utils/ECDSA.sol)
/// @author Modified from OpenZeppelin
/// (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/ECDSA.sol)
///
/// @dev Note:
/// - The recovery functions use the ecrecover precompile (0x1).
/// - As of Solady version 0.0.68, the `recover` variants will revert upon recovery failure.
///   This is for more safety by default.
///   Use the `tryRecover` variants if you need to get the zero address back
///   upon recovery failure instead.
/// - As of Solady version 0.0.134, all `bytes signature` variants accept both
///   regular 65-byte `(r, s, v)` and EIP-2098 `(r, vs)` short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098
///   This is for calldata efficiency on smart accounts prevalent on L2s.
///
/// WARNING! Do NOT directly use signatures as unique identifiers:
/// - The recovery operations do NOT check if a signature is non-malleable.
/// - Use a nonce in the digest to prevent replay attacks on the same contract.
/// - Use EIP-712 for the digest to prevent replay attacks across different chains and contracts.
///   EIP-712 also enables readable signing of typed data for better user safety.
/// - If you need a unique hash from a signature, please use the `canonicalHash` functions.
library ECDSA {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                         CONSTANTS                          */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The order of the secp256k1 elliptic curve.
    uint256 internal constant N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

    /// @dev `N/2 + 1`. Used for checking the malleability of the signature.
    uint256 private constant _HALF_N_PLUS_1 = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a1;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                        CUSTOM ERRORS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev The signature is invalid.
    error InvalidSignature();

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    RECOVERY OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function recover(bytes32 hash, bytes memory signature) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            for { let m := mload(0x40) } 1 {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            } {
                switch mload(signature)
                case 64 {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                    mstore(0x60, mload(add(signature, 0x40))) // `s`.
                }
                default { continue }
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) // `r`.
                result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                if returndatasize() { break }
            }
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function recoverCalldata(bytes32 hash, bytes calldata signature) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            for { let m := mload(0x40) } 1 {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            } {
                switch signature.length
                case 64 {
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                    calldatacopy(0x40, signature.offset, 0x40) // Copy `r` and `s`.
                }
                default { continue }
                mstore(0x00, hash)
                result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                if returndatasize() { break }
            }
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the EIP-2098 short form signature defined by `r` and `vs`.
    function recover(bytes32 hash, bytes32 r, bytes32 vs) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, hash)
            mstore(0x20, add(shr(255, vs), 27)) // `v`.
            mstore(0x40, r)
            mstore(0x60, shr(1, shl(1, vs))) // `s`.
            result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) // Restore the zero slot.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the signature defined by `v`, `r`, `s`.
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, hash)
            mstore(0x20, and(v, 0xff))
            mstore(0x40, r)
            mstore(0x60, s)
            result := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
            if iszero(returndatasize()) {
                mstore(0x00, 0x8baa579f) // `InvalidSignature()`.
                revert(0x1c, 0x04)
            }
            mstore(0x60, 0) // Restore the zero slot.
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   TRY-RECOVER OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // WARNING!
    // These functions will NOT revert upon recovery failure.
    // Instead, they will return the zero address upon recovery failure.
    // It is critical that the returned address is NEVER compared against
    // a zero address (e.g. an uninitialized address variable).

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function tryRecover(bytes32 hash, bytes memory signature) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            for { let m := mload(0x40) } 1 { } {
                switch mload(signature)
                case 64 {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                    mstore(0x60, mload(add(signature, 0x40))) // `s`.
                }
                default { break }
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) // `r`.
                pop(staticcall(gas(), 1, 0x00, 0x80, 0x40, 0x20))
                mstore(0x60, 0) // Restore the zero slot.
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                result := mload(xor(0x60, returndatasize()))
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`, and the `signature`.
    function tryRecoverCalldata(bytes32 hash, bytes calldata signature) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            for { let m := mload(0x40) } 1 { } {
                switch signature.length
                case 64 {
                    let vs := calldataload(add(signature.offset, 0x20))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, calldataload(signature.offset)) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                    calldatacopy(0x40, signature.offset, 0x40) // Copy `r` and `s`.
                }
                default { break }
                mstore(0x00, hash)
                pop(staticcall(gas(), 1, 0x00, 0x80, 0x40, 0x20))
                mstore(0x60, 0) // Restore the zero slot.
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                result := mload(xor(0x60, returndatasize()))
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the EIP-2098 short form signature defined by `r` and `vs`.
    function tryRecover(bytes32 hash, bytes32 r, bytes32 vs) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, hash)
            mstore(0x20, add(shr(255, vs), 27)) // `v`.
            mstore(0x40, r)
            mstore(0x60, shr(1, shl(1, vs))) // `s`.
            pop(staticcall(gas(), 1, 0x00, 0x80, 0x40, 0x20))
            mstore(0x60, 0) // Restore the zero slot.
            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /// @dev Recovers the signer's address from a message digest `hash`,
    /// and the signature defined by `v`, `r`, `s`.
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal view returns (address result) {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40) // Cache the free memory pointer.
            mstore(0x00, hash)
            mstore(0x20, and(v, 0xff))
            mstore(0x40, r)
            mstore(0x60, s)
            pop(staticcall(gas(), 1, 0x00, 0x80, 0x40, 0x20))
            mstore(0x60, 0) // Restore the zero slot.
            // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
            result := mload(xor(0x60, returndatasize()))
            mstore(0x40, m) // Restore the free memory pointer.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an Ethereum Signed Message, created from a `hash`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            result := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }
    }

    /// @dev Returns an Ethereum Signed Message, created from `s`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://ethereum.org/en/developers/docs/apis/json-rpc/#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    /// Note: Supports lengths of `s` up to 999999 bytes.
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let sLength := mload(s)
            let o := 0x20
            mstore(o, "\x19Ethereum Signed Message:\n") // 26 bytes, zero-right-padded.
            mstore(0x00, 0x00)
            // Convert the `s.length` to ASCII decimal representation: `base10(s.length)`.
            for { let temp := sLength } 1 { } {
                o := sub(o, 1)
                mstore8(o, add(48, mod(temp, 10)))
                temp := div(temp, 10)
                if iszero(temp) { break }
            }
            let n := sub(0x3a, o) // Header length: `26 + 32 - o`.
            // Throw an out-of-offset error (consumes all gas) if the header exceeds 32 bytes.
            returndatacopy(returndatasize(), returndatasize(), gt(n, 0x20))
            mstore(s, or(mload(0x00), mload(n))) // Temporarily store the header.
            result := keccak256(add(s, sub(0x20, n)), add(n, sLength))
            mstore(s, sLength) // Restore the length.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  CANONICAL HASH FUNCTIONS                  */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // The following functions return the hash of the signature in its canonicalized format,
    // which is the 65-byte `abi.encodePacked(r, s, uint8(v))`, where `v` is either 27 or 28.
    // If `s` is greater than `N / 2` then it will be converted to `N - s`
    // and the `v` value will be flipped.
    // If the signature has an invalid length, or if `v` is invalid,
    // a uniquely corrupt hash will be returned.
    // These functions are useful for "poor-mans-VRF".

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(bytes memory signature) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let l := mload(signature)
            for { } 1 { } {
                mstore(0x00, mload(add(signature, 0x20))) // `r`.
                let s := mload(add(signature, 0x40))
                let v := mload(add(signature, 0x41))
                if eq(l, 64) {
                    v := add(shr(255, s), 27)
                    s := shr(1, shl(1, s))
                }
                if iszero(lt(s, _HALF_N_PLUS_1)) {
                    v := xor(v, 7)
                    s := sub(N, s)
                }
                mstore(0x21, v)
                mstore(0x20, s)
                result := keccak256(0x00, 0x41)
                mstore(0x21, 0) // Restore the overwritten part of the free memory pointer.
                break
            }

            // If the length is neither 64 nor 65, return a uniquely corrupted hash.
            if iszero(lt(sub(l, 64), 2)) {
                // `bytes4(keccak256("InvalidSignatureLength"))`.
                result := xor(keccak256(add(signature, 0x20), l), 0xd62f1ab2)
            }
        }
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHashCalldata(bytes calldata signature) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            for { } 1 { } {
                mstore(0x00, calldataload(signature.offset)) // `r`.
                let s := calldataload(add(signature.offset, 0x20))
                let v := calldataload(add(signature.offset, 0x21))
                if eq(signature.length, 64) {
                    v := add(shr(255, s), 27)
                    s := shr(1, shl(1, s))
                }
                if iszero(lt(s, _HALF_N_PLUS_1)) {
                    v := xor(v, 7)
                    s := sub(N, s)
                }
                mstore(0x21, v)
                mstore(0x20, s)
                result := keccak256(0x00, 0x41)
                mstore(0x21, 0) // Restore the overwritten part of the free memory pointer.
                break
            }
            // If the length is neither 64 nor 65, return a uniquely corrupted hash.
            if iszero(lt(sub(signature.length, 64), 2)) {
                calldatacopy(mload(0x40), signature.offset, signature.length)
                // `bytes4(keccak256("InvalidSignatureLength"))`.
                result := xor(keccak256(mload(0x40), signature.length), 0xd62f1ab2)
            }
        }
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(bytes32 r, bytes32 vs) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, r) // `r`.
            let v := add(shr(255, vs), 27)
            let s := shr(1, shl(1, vs))
            mstore(0x21, v)
            mstore(0x20, s)
            result := keccak256(0x00, 0x41)
            mstore(0x21, 0) // Restore the overwritten part of the free memory pointer.
        }
    }

    /// @dev Returns the canonical hash of `signature`.
    function canonicalHash(uint8 v, bytes32 r, bytes32 s) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, r) // `r`.
            if iszero(lt(s, _HALF_N_PLUS_1)) {
                v := xor(v, 7)
                s := sub(N, s)
            }
            mstore(0x21, v)
            mstore(0x20, s)
            result := keccak256(0x00, 0x41)
            mstore(0x21, 0) // Restore the overwritten part of the free memory pointer.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EMPTY CALLDATA HELPERS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an empty calldata bytes.
    function emptySignature() internal pure returns (bytes calldata signature) {
        /// @solidity memory-safe-assembly
        assembly {
            signature.length := 0
        }
    }
}

// node_modules/@rhinestone/modulekit/src/module-bases/utils/ERC7579Constants.sol

uint256 constant MODULE_TYPE_VALIDATOR_0 = 1;
uint256 constant MODULE_TYPE_EXECUTOR_0 = 2;
uint256 constant MODULE_TYPE_FALLBACK_0 = 3;
uint256 constant MODULE_TYPE_HOOK_0 = 4;
uint256 constant MODULE_TYPE_POLICY = 5;
uint256 constant MODULE_TYPE_SIGNER = 6;
uint256 constant MODULE_TYPE_STATELESS_VALIDATOR = 7;

// node_modules/@ERC4337/account-abstraction/contracts/utils/Exec.sol

// solhint-disable no-inline-assembly

/**
 * Utility functions helpful when making different kinds of contract calls in Solidity.
 */
library Exec {
    function call(address to, uint256 value, bytes memory data, uint256 txGas) internal returns (bool success) {
        assembly ("memory-safe") {
            success := call(txGas, to, value, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function staticcall(address to, bytes memory data, uint256 txGas) internal view returns (bool success) {
        assembly ("memory-safe") {
            success := staticcall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    function delegateCall(address to, bytes memory data, uint256 txGas) internal returns (bool success) {
        assembly ("memory-safe") {
            success := delegatecall(txGas, to, add(data, 0x20), mload(data), 0, 0)
        }
    }

    // get returned data from last call or calldelegate
    function getReturnData(uint256 maxLen) internal pure returns (bytes memory returnData) {
        assembly ("memory-safe") {
            let len := returndatasize()
            if gt(len, maxLen) { len := maxLen }
            let ptr := mload(0x40)
            mstore(0x40, add(ptr, add(len, 0x20)))
            mstore(ptr, len)
            returndatacopy(add(ptr, 0x20), 0, len)
            returnData := ptr
        }
    }

    // revert with explicit byte array (probably reverted info from call)
    function revertWithData(bytes memory returnData) internal pure {
        assembly ("memory-safe") {
            revert(add(returnData, 32), mload(returnData))
        }
    }

    function callAndRevert(address to, bytes memory data, uint256 maxLen) internal {
        bool success = call(to, 0, data, gasleft());
        if (!success) {
            revertWithData(getReturnData(maxLen));
        }
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/GasDebug.sol

contract GasDebug {
    // Phase 0: account creation
    // Phase 1: validation
    // Phase 2: execution
    mapping(address account => mapping(uint256 phase => uint256 gas)) gasConsumed;

    function setGasConsumed(address account, uint256 phase, uint256 gas) internal {
        gasConsumed[account][phase] = gas;
    }

    function getGasConsumed(address account, uint256 phase) public view returns (uint256) {
        return gasConsumed[account][phase];
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/Helpers.sol

/* solhint-disable no-inline-assembly */

/*
  * For simulation purposes, validateUserOp (and validatePaymasterUserOp)
  * must return this value in case of signature failure, instead of revert.
  */
uint256 constant SIG_VALIDATION_FAILED = 1;

/*
 * For simulation purposes, validateUserOp (and validatePaymasterUserOp)
 * return this value on success.
 */
uint256 constant SIG_VALIDATION_SUCCESS = 0;

/**
 * Returned data from validateUserOp.
 * validateUserOp returns a uint256, which is created by `_packedValidationData` and
 * parsed by `_parseValidationData`.
 * @param aggregator  - address(0) - The account validated the signature by itself.
 *                      address(1) - The account failed to validate the signature.
 *                      otherwise - This is an address of a signature aggregator that must
 *                                  be used to validate the signature.
 * @param validAfter  - This UserOp is valid only after this timestamp.
 * @param validaUntil - This UserOp is valid only up to this timestamp.
 */
struct ValidationData {
    address aggregator;
    uint48 validAfter;
    uint48 validUntil;
}

/**
 * Extract sigFailed, validAfter, validUntil.
 * Also convert zero validUntil to type(uint48).max.
 * @param validationData - The packed validation data.
 */
function _parseValidationData(uint256 validationData) pure returns (ValidationData memory data) {
    address aggregator = address(uint160(validationData));
    uint48 validUntil = uint48(validationData >> 160);
    if (validUntil == 0) {
        validUntil = type(uint48).max;
    }
    uint48 validAfter = uint48(validationData >> (48 + 160));
    return ValidationData(aggregator, validAfter, validUntil);
}

/**
 * Helper to pack the return value for validateUserOp.
 * @param data - The ValidationData to pack.
 */
function _packValidationData_0(ValidationData memory data) pure returns (uint256) {
    return uint160(data.aggregator) | (uint256(data.validUntil) << 160) | (uint256(data.validAfter) << (160 + 48));
}

/**
 * Helper to pack the return value for validateUserOp, when not using an aggregator.
 * @param sigFailed  - True for signature failure, false for success.
 * @param validUntil - Last timestamp this UserOperation is valid (or zero for infinite).
 * @param validAfter - First timestamp this UserOperation is valid.
 */
function _packValidationData_1(bool sigFailed, uint48 validUntil, uint48 validAfter) pure returns (uint256) {
    return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
}

/**
 * keccak function over calldata.
 * @dev copy calldata into memory, do keccak and drop allocated memory. Strangely, this is more efficient than letting
 * solidity do it.
 */
function calldataKeccak(bytes calldata data) pure returns (bytes32 ret) {
    assembly ("memory-safe") {
        let mem := mload(0x40)
        let len := data.length
        calldatacopy(mem, data.offset, len)
        ret := keccak256(mem, len)
    }
}

/**
 * The minimum of two numbers.
 * @param a - First number.
 * @param b - Second number.
 */
function min(uint256 a, uint256 b) pure returns (uint256) {
    return a < b ? a : b;
}

// node_modules/@openzeppelin/contracts/utils/introspection/IERC165.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/introspection/IERC165.sol)

/**
 * @dev Interface of the ERC-165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[ERC].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165_0 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[ERC section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}

// node_modules/forge-std/src/interfaces/IERC165.sol

interface IERC165_1 {
    /// @notice Query if a contract implements an interface
    /// @param interfaceID The interface identifier, as specified in ERC-165
    /// @dev Interface identification is specified in ERC-165. This function
    /// uses less than 30,000 gas.
    /// @return `true` if the contract implements `interfaceID` and
    /// `interfaceID` is not 0xffffffff, `false` otherwise
    function supportsInterface(bytes4 interfaceID) external view returns (bool);
}

// node_modules/@rhinestone/modulekit/src/module-bases/interfaces/IERC7484.sol

interface IERC7484 {
    event NewTrustedAttesters();
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*          Check with Registry internal attesters            */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function check(address module) external view;

    function checkForAccount(address smartAccount, address module) external view;

    function check(address module, uint256 moduleType) external view;

    function checkForAccount(address smartAccount, address module, uint256 moduleType) external view;

    /**
     * Allows Smart Accounts - the end users of the registry - to appoint
     * one or many attesters as trusted.
     * @dev this function reverts, if address(0), or duplicates are provided in attesters[]
     *
     * @param threshold The minimum number of attestations required for a module
     *                  to be considered secure.
     * @param attesters The addresses of the attesters to be trusted.
     */
    function trustAttesters(uint8 threshold, address[] calldata attesters) external;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*              Check with external attester(s)               */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    function check(address module, address[] calldata attesters, uint256 threshold) external view;

    function check(address module, uint256 moduleType, address[] calldata attesters, uint256 threshold) external view;
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/INonceManager.sol

interface INonceManager {
    /**
     * Return the next nonce for this sender.
     * Within a given key, the nonce values are sequenced (starting with zero, and incremented by one on each userop)
     * But UserOp with different keys can come with arbitrary order.
     *
     * @param sender the account address
     * @param key the high 192 bit of the nonce
     * @return nonce a full nonce to pass for next UserOp with this sender.
     */
    function getNonce(address sender, uint192 key) external view returns (uint256 nonce);

    /**
     * Manually increment the nonce of the sender.
     * This method is exposed just for completeness..
     * Account does NOT need to call it, neither during validation, nor elsewhere,
     * as the EntryPoint will update the nonce regardless.
     * Possible use-case is call it with various keys to "initialize" their nonces to one, so that future
     * UserOperations will not pay extra for the first transaction with a given key.
     */
    function incrementNonce(uint192 key) external;
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IStakeManager.sol

/**
 * Manage deposits and stakes.
 * Deposit is just a balance used to pay for UserOperations (either by a paymaster or an account).
 * Stake is value locked for at least "unstakeDelay" by the staked entity.
 */
interface IStakeManager {
    event Deposited(address indexed account, uint256 totalDeposit);

    event Withdrawn(address indexed account, address withdrawAddress, uint256 amount);

    // Emitted when stake or unstake delay are modified.
    event StakeLocked(address indexed account, uint256 totalStaked, uint256 unstakeDelaySec);

    // Emitted once a stake is scheduled for withdrawal.
    event StakeUnlocked(address indexed account, uint256 withdrawTime);

    event StakeWithdrawn(address indexed account, address withdrawAddress, uint256 amount);

    /**
     * @param deposit         - The entity's deposit.
     * @param staked          - True if this entity is staked.
     * @param stake           - Actual amount of ether staked for this entity.
     * @param unstakeDelaySec - Minimum delay to withdraw the stake.
     * @param withdrawTime    - First block timestamp where 'withdrawStake' will be callable, or zero if already locked.
     * @dev Sizes were chosen so that deposit fits into one cell (used during handleOp)
     *      and the rest fit into a 2nd cell (used during stake/unstake)
     *      - 112 bit allows for 10^15 eth
     *      - 48 bit for full timestamp
     *      - 32 bit allows 150 years for unstake delay
     */
    struct DepositInfo {
        uint256 deposit;
        bool staked;
        uint112 stake;
        uint32 unstakeDelaySec;
        uint48 withdrawTime;
    }

    // API struct used by getStakeInfo and simulateValidation.
    struct StakeInfo {
        uint256 stake;
        uint256 unstakeDelaySec;
    }

    /**
     * Get deposit info.
     * @param account - The account to query.
     * @return info   - Full deposit information of given account.
     */
    function getDepositInfo(address account) external view returns (DepositInfo memory info);

    /**
     * Get account balance.
     * @param account - The account to query.
     * @return        - The deposit (for gas payment) of the account.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * Add to the deposit of the given account.
     * @param account - The account to add to.
     */
    function depositTo(address account) external payable;

    /**
     * Add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param _unstakeDelaySec - The new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 _unstakeDelaySec) external payable;

    /**
     * Attempt to unlock the stake.
     * The value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external;

    /**
     * Withdraw from the (unlocked) stake.
     * Must first call unlockStake and wait for the unstakeDelay to pass.
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external;

    /**
     * Withdraw from the deposit.
     * @param withdrawAddress - The address to send withdrawn value.
     * @param withdrawAmount  - The amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external;
}

// node_modules/@rhinestone/modulekit/src/module-bases/interfaces/IStatelessValidator.sol

interface IStatelessValidator {
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool);
}

// node_modules/solady/src/utils/LibSort.sol

/// @notice Optimized sorts and operations for sorted arrays.
/// @author Solady (https://github.com/Vectorized/solady/blob/main/src/utils/LibSort.sol)
library LibSort {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INSERTION SORT                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // - Faster on small arrays (32 or lesser elements).
    // - Faster on almost sorted arrays.
    // - Smaller bytecode (about 300 bytes smaller than sort, which uses intro-quicksort).
    // - May be suitable for view functions intended for off-chain querying.

    /// @dev Sorts the array in-place with insertion sort.
    function insertionSort(uint256[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let n := mload(a) // Length of `a`.
            mstore(a, 0) // For insertion sort's inner loop to terminate.
            let h := add(a, shl(5, n)) // High slot.
            let w := not(0x1f)
            for { let i := add(a, 0x20) } 1 { } {
                i := add(i, 0x20)
                if gt(i, h) { break }
                let k := mload(i) // Key.
                let j := add(i, w) // The slot before the current slot.
                let v := mload(j) // The value of `j`.
                if iszero(gt(v, k)) { continue }
                for { } 1 { } {
                    mstore(add(j, 0x20), v)
                    j := add(j, w) // `sub(j, 0x20)`.
                    v := mload(j)
                    if iszero(gt(v, k)) { break }
                }
                mstore(add(j, 0x20), k)
            }
            mstore(a, n) // Restore the length of `a`.
        }
    }

    /// @dev Sorts the array in-place with insertion sort.
    function insertionSort(int256[] memory a) internal pure {
        _flipSign(a);
        insertionSort(_toUints(a));
        _flipSign(a);
    }

    /// @dev Sorts the array in-place with insertion sort.
    function insertionSort(address[] memory a) internal pure {
        insertionSort(_toUints(a));
    }

    /// @dev Sorts the array in-place with insertion sort.
    function insertionSort(bytes32[] memory a) internal pure {
        insertionSort(_toUints(a));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      INTRO-QUICKSORT                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // - Faster on larger arrays (more than 32 elements).
    // - Robust performance.
    // - Larger bytecode.

    /// @dev Sorts the array in-place with intro-quicksort.
    function sort(uint256[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            function swap(a_, b_) -> _a, _b {
                _b := a_
                _a := b_
            }
            function mswap(i_, j_) {
                let t_ := mload(i_)
                mstore(i_, mload(j_))
                mstore(j_, t_)
            }
            function sortInner(w_, l_, h_) {
                // Do insertion sort if `h_ - l_ <= 0x20 * 12`.
                // Threshold is fine-tuned via trial and error.
                if iszero(gt(sub(h_, l_), 0x180)) {
                    // Hardcode sort the first 2 elements.
                    let i_ := add(l_, 0x20)
                    if iszero(lt(mload(l_), mload(i_))) { mswap(i_, l_) }
                    for { } 1 { } {
                        i_ := add(i_, 0x20)
                        if gt(i_, h_) { break }
                        let k_ := mload(i_) // Key.
                        let j_ := add(i_, w_) // The slot before the current slot.
                        let v_ := mload(j_) // The value of `j_`.
                        if iszero(gt(v_, k_)) { continue }
                        for { } 1 { } {
                            mstore(add(j_, 0x20), v_)
                            j_ := add(j_, w_)
                            v_ := mload(j_)
                            if iszero(gt(v_, k_)) { break }
                        }
                        mstore(add(j_, 0x20), k_)
                    }
                    leave
                }
                // Pivot slot is the average of `l_` and `h_`.
                let p_ := add(shl(5, shr(6, add(l_, h_))), and(31, l_))
                // Median of 3 with sorting.
                {
                    let e0_ := mload(l_)
                    let e1_ := mload(p_)
                    if iszero(lt(e0_, e1_)) { e0_, e1_ := swap(e0_, e1_) }
                    let e2_ := mload(h_)
                    if iszero(lt(e1_, e2_)) {
                        e1_, e2_ := swap(e1_, e2_)
                        if iszero(lt(e0_, e1_)) { e0_, e1_ := swap(e0_, e1_) }
                    }
                    mstore(h_, e2_)
                    mstore(p_, e1_)
                    mstore(l_, e0_)
                }
                // Hoare's partition.
                {
                    // The value of the pivot slot.
                    let x_ := mload(p_)
                    p_ := h_
                    for { let i_ := l_ } 1 { } {
                        for { } 1 { } {
                            i_ := add(0x20, i_)
                            if iszero(gt(x_, mload(i_))) { break }
                        }
                        let j_ := p_
                        for { } 1 { } {
                            j_ := add(w_, j_)
                            if iszero(lt(x_, mload(j_))) { break }
                        }
                        p_ := j_
                        if iszero(lt(i_, p_)) { break }
                        mswap(i_, p_)
                    }
                }
                if iszero(eq(add(p_, 0x20), h_)) { sortInner(w_, add(p_, 0x20), h_) }
                if iszero(eq(p_, l_)) { sortInner(w_, l_, p_) }
            }

            for { let n := mload(a) } iszero(lt(n, 2)) { } {
                let w := not(0x1f) // `-0x20`.
                let l := add(a, 0x20) // Low slot.
                let h := add(a, shl(5, n)) // High slot.
                let j := h
                // While `mload(j - 0x20) <= mload(j): j -= 0x20`.
                for { } iszero(gt(mload(add(w, j)), mload(j))) { } { j := add(w, j) }
                // If the array is already sorted, break.
                if iszero(gt(j, l)) { break }
                // While `mload(j - 0x20) >= mload(j): j -= 0x20`.
                for { j := h } iszero(lt(mload(add(w, j)), mload(j))) { } { j := add(w, j) }
                // If the array is reversed sorted.
                if iszero(gt(j, l)) {
                    for { } 1 { } {
                        let t := mload(l)
                        mstore(l, mload(h))
                        mstore(h, t)
                        h := add(w, h)
                        l := add(l, 0x20)
                        if iszero(lt(l, h)) { break }
                    }
                    break
                }
                mstore(a, 0) // For insertion sort's inner loop to terminate.
                sortInner(w, l, h)
                mstore(a, n) // Restore the length of `a`.
                break
            }
        }
    }

    /// @dev Sorts the array in-place with intro-quicksort.
    function sort(int256[] memory a) internal pure {
        _flipSign(a);
        sort(_toUints(a));
        _flipSign(a);
    }

    /// @dev Sorts the array in-place with intro-quicksort.
    function sort(address[] memory a) internal pure {
        sort(_toUints(a));
    }

    /// @dev Sorts the array in-place with intro-quicksort.
    function sort(bytes32[] memory a) internal pure {
        sort(_toUints(a));
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                  OTHER USEFUL OPERATIONS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // For performance, the `uniquifySorted` methods will not revert if the
    // array is not sorted -- it will simply remove consecutive duplicate elements.

    /// @dev Removes duplicate elements from a ascendingly sorted memory array.
    function uniquifySorted(uint256[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            // If the length of `a` is greater than 1.
            if iszero(lt(mload(a), 2)) {
                let x := add(a, 0x20)
                let y := add(a, 0x40)
                let end := add(a, shl(5, add(mload(a), 1)))
                for { } 1 { } {
                    if iszero(eq(mload(x), mload(y))) {
                        x := add(x, 0x20)
                        mstore(x, mload(y))
                    }
                    y := add(y, 0x20)
                    if eq(y, end) { break }
                }
                mstore(a, shr(5, sub(x, a)))
            }
        }
    }

    /// @dev Removes duplicate elements from a ascendingly sorted memory array.
    function uniquifySorted(int256[] memory a) internal pure {
        uniquifySorted(_toUints(a));
    }

    /// @dev Removes duplicate elements from a ascendingly sorted memory array.
    function uniquifySorted(address[] memory a) internal pure {
        uniquifySorted(_toUints(a));
    }

    /// @dev Removes duplicate elements from a ascendingly sorted memory array.
    function uniquifySorted(bytes32[] memory a) internal pure {
        uniquifySorted(_toUints(a));
    }

    /// @dev Returns whether `a` contains `needle`, and the index of `needle`.
    /// `index` precedence: equal to > nearest before > nearest after.
    function searchSorted(uint256[] memory a, uint256 needle) internal pure returns (bool found, uint256 index) {
        (found, index) = _searchSorted(a, needle, 0);
    }

    /// @dev Returns whether `a` contains `needle`, and the index of `needle`.
    /// `index` precedence: equal to > nearest before > nearest after.
    function searchSorted(int256[] memory a, int256 needle) internal pure returns (bool found, uint256 index) {
        (found, index) = _searchSorted(_toUints(a), uint256(needle), 1 << 255);
    }

    /// @dev Returns whether `a` contains `needle`, and the index of `needle`.
    /// `index` precedence: equal to > nearest before > nearest after.
    function searchSorted(address[] memory a, address needle) internal pure returns (bool found, uint256 index) {
        (found, index) = _searchSorted(_toUints(a), uint160(needle), 0);
    }

    /// @dev Returns whether `a` contains `needle`, and the index of `needle`.
    /// `index` precedence: equal to > nearest before > nearest after.
    function searchSorted(bytes32[] memory a, bytes32 needle) internal pure returns (bool found, uint256 index) {
        (found, index) = _searchSorted(_toUints(a), uint256(needle), 0);
    }

    /// @dev Returns whether `a` contains `needle`.
    function inSorted(uint256[] memory a, uint256 needle) internal pure returns (bool found) {
        (found,) = searchSorted(a, needle);
    }

    /// @dev Returns whether `a` contains `needle`.
    function inSorted(int256[] memory a, int256 needle) internal pure returns (bool found) {
        (found,) = searchSorted(a, needle);
    }

    /// @dev Returns whether `a` contains `needle`.
    function inSorted(address[] memory a, address needle) internal pure returns (bool found) {
        (found,) = searchSorted(a, needle);
    }

    /// @dev Returns whether `a` contains `needle`.
    function inSorted(bytes32[] memory a, bytes32 needle) internal pure returns (bool found) {
        (found,) = searchSorted(a, needle);
    }

    /// @dev Reverses the array in-place.
    function reverse(uint256[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            if iszero(lt(mload(a), 2)) {
                let s := 0x20
                let w := not(0x1f)
                let h := add(a, shl(5, mload(a)))
                for { a := add(a, s) } 1 { } {
                    let t := mload(a)
                    mstore(a, mload(h))
                    mstore(h, t)
                    h := add(h, w)
                    a := add(a, s)
                    if iszero(lt(a, h)) { break }
                }
            }
        }
    }

    /// @dev Reverses the array in-place.
    function reverse(int256[] memory a) internal pure {
        reverse(_toUints(a));
    }

    /// @dev Reverses the array in-place.
    function reverse(address[] memory a) internal pure {
        reverse(_toUints(a));
    }

    /// @dev Reverses the array in-place.
    function reverse(bytes32[] memory a) internal pure {
        reverse(_toUints(a));
    }

    /// @dev Returns a copy of the array.
    function copy(uint256[] memory a) internal pure returns (uint256[] memory result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := mload(0x40)
            let end := add(add(result, 0x20), shl(5, mload(a)))
            let o := result
            for { let d := sub(a, result) } 1 { } {
                mstore(o, mload(add(o, d)))
                o := add(0x20, o)
                if eq(o, end) { break }
            }
            mstore(0x40, o)
        }
    }

    /// @dev Returns a copy of the array.
    function copy(int256[] memory a) internal pure returns (int256[] memory result) {
        result = _toInts(copy(_toUints(a)));
    }

    /// @dev Returns a copy of the array.
    function copy(address[] memory a) internal pure returns (address[] memory result) {
        result = _toAddresses(copy(_toUints(a)));
    }

    /// @dev Returns a copy of the array.
    function copy(bytes32[] memory a) internal pure returns (bytes32[] memory result) {
        result = _toBytes32s(copy(_toUints(a)));
    }

    /// @dev Returns whether the array is sorted in ascending order.
    function isSorted(uint256[] memory a) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := 1
            if iszero(lt(mload(a), 2)) {
                let end := add(a, shl(5, mload(a)))
                for { a := add(a, 0x20) } 1 { } {
                    let p := mload(a)
                    a := add(a, 0x20)
                    result := iszero(gt(p, mload(a)))
                    if iszero(mul(result, xor(a, end))) { break }
                }
            }
        }
    }

    /// @dev Returns whether the array is sorted in ascending order.
    function isSorted(int256[] memory a) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := 1
            if iszero(lt(mload(a), 2)) {
                let end := add(a, shl(5, mload(a)))
                for { a := add(a, 0x20) } 1 { } {
                    let p := mload(a)
                    a := add(a, 0x20)
                    result := iszero(sgt(p, mload(a)))
                    if iszero(mul(result, xor(a, end))) { break }
                }
            }
        }
    }

    /// @dev Returns whether the array is sorted in ascending order.
    function isSorted(address[] memory a) internal pure returns (bool result) {
        result = isSorted(_toUints(a));
    }

    /// @dev Returns whether the array is sorted in ascending order.
    function isSorted(bytes32[] memory a) internal pure returns (bool result) {
        result = isSorted(_toUints(a));
    }

    /// @dev Returns whether the array is strictly ascending (sorted and uniquified).
    function isSortedAndUniquified(uint256[] memory a) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := 1
            if iszero(lt(mload(a), 2)) {
                let end := add(a, shl(5, mload(a)))
                for { a := add(a, 0x20) } 1 { } {
                    let p := mload(a)
                    a := add(a, 0x20)
                    result := lt(p, mload(a))
                    if iszero(mul(result, xor(a, end))) { break }
                }
            }
        }
    }

    /// @dev Returns whether the array is strictly ascending (sorted and uniquified).
    function isSortedAndUniquified(int256[] memory a) internal pure returns (bool result) {
        /// @solidity memory-safe-assembly
        assembly {
            result := 1
            if iszero(lt(mload(a), 2)) {
                let end := add(a, shl(5, mload(a)))
                for { a := add(a, 0x20) } 1 { } {
                    let p := mload(a)
                    a := add(a, 0x20)
                    result := slt(p, mload(a))
                    if iszero(mul(result, xor(a, end))) { break }
                }
            }
        }
    }

    /// @dev Returns whether the array is strictly ascending (sorted and uniquified).
    function isSortedAndUniquified(address[] memory a) internal pure returns (bool result) {
        result = isSortedAndUniquified(_toUints(a));
    }

    /// @dev Returns whether the array is strictly ascending (sorted and uniquified).
    function isSortedAndUniquified(bytes32[] memory a) internal pure returns (bool result) {
        result = isSortedAndUniquified(_toUints(a));
    }

    /// @dev Returns the sorted set difference of `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function difference(uint256[] memory a, uint256[] memory b) internal pure returns (uint256[] memory c) {
        c = _difference(a, b, 0);
    }

    /// @dev Returns the sorted set difference between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function difference(int256[] memory a, int256[] memory b) internal pure returns (int256[] memory c) {
        c = _toInts(_difference(_toUints(a), _toUints(b), 1 << 255));
    }

    /// @dev Returns the sorted set difference between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function difference(address[] memory a, address[] memory b) internal pure returns (address[] memory c) {
        c = _toAddresses(_difference(_toUints(a), _toUints(b), 0));
    }

    /// @dev Returns the sorted set difference between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function difference(bytes32[] memory a, bytes32[] memory b) internal pure returns (bytes32[] memory c) {
        c = _toBytes32s(_difference(_toUints(a), _toUints(b), 0));
    }

    /// @dev Returns the sorted set intersection between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function intersection(uint256[] memory a, uint256[] memory b) internal pure returns (uint256[] memory c) {
        c = _intersection(a, b, 0);
    }

    /// @dev Returns the sorted set intersection between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function intersection(int256[] memory a, int256[] memory b) internal pure returns (int256[] memory c) {
        c = _toInts(_intersection(_toUints(a), _toUints(b), 1 << 255));
    }

    /// @dev Returns the sorted set intersection between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function intersection(address[] memory a, address[] memory b) internal pure returns (address[] memory c) {
        c = _toAddresses(_intersection(_toUints(a), _toUints(b), 0));
    }

    /// @dev Returns the sorted set intersection between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function intersection(bytes32[] memory a, bytes32[] memory b) internal pure returns (bytes32[] memory c) {
        c = _toBytes32s(_intersection(_toUints(a), _toUints(b), 0));
    }

    /// @dev Returns the sorted set union of `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function union(uint256[] memory a, uint256[] memory b) internal pure returns (uint256[] memory c) {
        c = _union(a, b, 0);
    }

    /// @dev Returns the sorted set union of `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function union(int256[] memory a, int256[] memory b) internal pure returns (int256[] memory c) {
        c = _toInts(_union(_toUints(a), _toUints(b), 1 << 255));
    }

    /// @dev Returns the sorted set union between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function union(address[] memory a, address[] memory b) internal pure returns (address[] memory c) {
        c = _toAddresses(_union(_toUints(a), _toUints(b), 0));
    }

    /// @dev Returns the sorted set union between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function union(bytes32[] memory a, bytes32[] memory b) internal pure returns (bytes32[] memory c) {
        c = _toBytes32s(_union(_toUints(a), _toUints(b), 0));
    }

    /// @dev Cleans the upper 96 bits of the addresses.
    /// In case `a` is produced via assembly and might have dirty upper bits.
    function clean(address[] memory a) internal pure {
        /// @solidity memory-safe-assembly
        assembly {
            let addressMask := shr(96, not(0))
            for { let end := add(a, shl(5, mload(a))) } iszero(eq(a, end)) { } {
                a := add(a, 0x20)
                mstore(a, and(mload(a), addressMask))
            }
        }
    }

    /// @dev Sorts and uniquifies `keys`. Updates `values` with the grouped sums by key.
    function groupSum(uint256[] memory keys, uint256[] memory values) internal pure {
        uint256 m;
        /// @solidity memory-safe-assembly
        assembly {
            m := mload(0x40) // Cache the free memory pointer, for freeing the memory.
            if iszero(eq(mload(keys), mload(values))) {
                mstore(0x00, 0x4e487b71)
                mstore(0x20, 0x32) // Array out of bounds panic if the arrays lengths differ.
                revert(0x1c, 0x24)
            }
        }
        if (keys.length == uint256(0)) return;
        (uint256[] memory oriKeys, uint256[] memory oriValues) = (copy(keys), copy(values));
        insertionSort(keys); // Optimize for small `n` and bytecode size.
        uniquifySorted(keys);
        /// @solidity memory-safe-assembly
        assembly {
            let d := sub(values, keys)
            let w := not(0x1f)
            let s := add(keys, 0x20) // Location of `keys[0]`.
            mstore(values, mload(keys)) // Truncate.
            calldatacopy(add(s, d), calldatasize(), shl(5, mload(keys))) // Zeroize.
            for { let i := shl(5, mload(oriKeys)) } 1 { } {
                let k := mload(add(oriKeys, i))
                let v := mload(add(oriValues, i))
                let j := s // Just do a linear scan to optimize for small `n` and bytecode size.
                for { } iszero(eq(mload(j), k)) { } { j := add(j, 0x20) }
                j := add(j, d) // Convert `j` to point into `values`.
                mstore(j, add(mload(j), v))
                if lt(mload(j), v) {
                    mstore(0x00, 0x4e487b71)
                    mstore(0x20, 0x11) // Overflow panic if the addition overflows.
                    revert(0x1c, 0x24)
                }
                i := add(i, w) // `sub(i, 0x20)`.
                if iszero(i) { break }
            }
            mstore(0x40, m) // Frees the memory allocated for the temporary copies.
        }
    }

    /// @dev Sorts and uniquifies `keys`. Updates `values` with the grouped sums by key.
    function groupSum(address[] memory keys, uint256[] memory values) internal pure {
        groupSum(_toUints(keys), values);
    }

    /// @dev Sorts and uniquifies `keys`. Updates `values` with the grouped sums by key.
    function groupSum(bytes32[] memory keys, uint256[] memory values) internal pure {
        groupSum(_toUints(keys), values);
    }

    /// @dev Sorts and uniquifies `keys`. Updates `values` with the grouped sums by key.
    function groupSum(int256[] memory keys, uint256[] memory values) internal pure {
        groupSum(_toUints(keys), values);
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                      PRIVATE HELPERS                       */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Reinterpret cast to an uint256 array.
    function _toUints(int256[] memory a) private pure returns (uint256[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            casted := a
        }
    }

    /// @dev Reinterpret cast to an uint256 array.
    function _toUints(address[] memory a) private pure returns (uint256[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            // As any address written to memory will have the upper 96 bits
            // of the word zeroized (as per Solidity spec), we can directly
            // compare these addresses as if they are whole uint256 words.
            casted := a
        }
    }

    /// @dev Reinterpret cast to an uint256 array.
    function _toUints(bytes32[] memory a) private pure returns (uint256[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            casted := a
        }
    }

    /// @dev Reinterpret cast to an int array.
    function _toInts(uint256[] memory a) private pure returns (int256[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            casted := a
        }
    }

    /// @dev Reinterpret cast to an address array.
    function _toAddresses(uint256[] memory a) private pure returns (address[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            casted := a
        }
    }

    /// @dev Reinterpret cast to an bytes32 array.
    function _toBytes32s(uint256[] memory a) private pure returns (bytes32[] memory casted) {
        /// @solidity memory-safe-assembly
        assembly {
            casted := a
        }
    }

    /// @dev Converts an array of signed integers to unsigned
    /// integers suitable for sorting or vice versa.
    function _flipSign(int256[] memory a) private pure {
        /// @solidity memory-safe-assembly
        assembly {
            let w := shl(255, 1)
            for { let end := add(a, shl(5, mload(a))) } iszero(eq(a, end)) { } {
                a := add(a, 0x20)
                mstore(a, add(mload(a), w))
            }
        }
    }

    /// @dev Returns whether `a` contains `needle`, and the index of `needle`.
    /// `index` precedence: equal to > nearest before > nearest after.
    function _searchSorted(
        uint256[] memory a,
        uint256 needle,
        uint256 signed
    )
        private
        pure
        returns (bool found, uint256 index)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let w := not(0)
            let l := 1
            let h := mload(a)
            let t := 0
            for { needle := add(signed, needle) } 1 { } {
                index := shr(1, add(l, h))
                t := add(signed, mload(add(a, shl(5, index))))
                if or(gt(l, h), eq(t, needle)) { break }
                // Decide whether to search the left or right half.
                if iszero(gt(needle, t)) {
                    h := add(index, w)
                    continue
                }
                l := add(index, 1)
            }
            // `index` will be zero in the case of an empty array,
            // or when the value is less than the smallest value in the array.
            found := eq(t, needle)
            t := iszero(iszero(index))
            index := mul(add(index, w), t)
            found := and(found, t)
        }
    }

    /// @dev Returns the sorted set difference of `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function _difference(
        uint256[] memory a,
        uint256[] memory b,
        uint256 signed
    )
        private
        pure
        returns (uint256[] memory c)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let s := 0x20
            let aEnd := add(a, shl(5, mload(a)))
            let bEnd := add(b, shl(5, mload(b)))
            c := mload(0x40) // Set `c` to the free memory pointer.
            a := add(a, s)
            b := add(b, s)
            let k := c
            for { } iszero(or(gt(a, aEnd), gt(b, bEnd))) { } {
                let u := mload(a)
                let v := mload(b)
                if iszero(xor(u, v)) {
                    a := add(a, s)
                    b := add(b, s)
                    continue
                }
                if iszero(lt(add(u, signed), add(v, signed))) {
                    b := add(b, s)
                    continue
                }
                k := add(k, s)
                mstore(k, u)
                a := add(a, s)
            }
            for { } iszero(gt(a, aEnd)) { } {
                k := add(k, s)
                mstore(k, mload(a))
                a := add(a, s)
            }
            mstore(c, shr(5, sub(k, c))) // Store the length of `c`.
            mstore(0x40, add(k, s)) // Allocate the memory for `c`.
        }
    }

    /// @dev Returns the sorted set intersection between `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function _intersection(
        uint256[] memory a,
        uint256[] memory b,
        uint256 signed
    )
        private
        pure
        returns (uint256[] memory c)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let s := 0x20
            let aEnd := add(a, shl(5, mload(a)))
            let bEnd := add(b, shl(5, mload(b)))
            c := mload(0x40) // Set `c` to the free memory pointer.
            a := add(a, s)
            b := add(b, s)
            let k := c
            for { } iszero(or(gt(a, aEnd), gt(b, bEnd))) { } {
                let u := mload(a)
                let v := mload(b)
                if iszero(xor(u, v)) {
                    k := add(k, s)
                    mstore(k, u)
                    a := add(a, s)
                    b := add(b, s)
                    continue
                }
                if iszero(lt(add(u, signed), add(v, signed))) {
                    b := add(b, s)
                    continue
                }
                a := add(a, s)
            }
            mstore(c, shr(5, sub(k, c))) // Store the length of `c`.
            mstore(0x40, add(k, s)) // Allocate the memory for `c`.
        }
    }

    /// @dev Returns the sorted set union of `a` and `b`.
    /// Note: Behaviour is undefined if inputs are not sorted and uniquified.
    function _union(uint256[] memory a, uint256[] memory b, uint256 signed) private pure returns (uint256[] memory c) {
        /// @solidity memory-safe-assembly
        assembly {
            let s := 0x20
            let aEnd := add(a, shl(5, mload(a)))
            let bEnd := add(b, shl(5, mload(b)))
            c := mload(0x40) // Set `c` to the free memory pointer.
            a := add(a, s)
            b := add(b, s)
            let k := c
            for { } iszero(or(gt(a, aEnd), gt(b, bEnd))) { } {
                let u := mload(a)
                let v := mload(b)
                if iszero(xor(u, v)) {
                    k := add(k, s)
                    mstore(k, u)
                    a := add(a, s)
                    b := add(b, s)
                    continue
                }
                if iszero(lt(add(u, signed), add(v, signed))) {
                    k := add(k, s)
                    mstore(k, v)
                    b := add(b, s)
                    continue
                }
                k := add(k, s)
                mstore(k, u)
                a := add(a, s)
            }
            for { } iszero(gt(a, aEnd)) { } {
                k := add(k, s)
                mstore(k, mload(a))
                a := add(a, s)
            }
            for { } iszero(gt(b, bEnd)) { } {
                k := add(k, s)
                mstore(k, mload(b))
                b := add(b, s)
            }
            mstore(c, shr(5, sub(k, c))) // Store the length of `c`.
            mstore(0x40, add(k, s)) // Allocate the memory for `c`.
        }
    }
}

// node_modules/@rhinestone/modulekit/src/accounts/common/lib/ModeLib.sol

/**
 * @title ModeLib
 * @author rhinestone | zeroknots.eth, Konrad Kopp (@kopy-kat)
 * To allow smart accounts to be very simple, but allow for more complex execution, A custom mode
 * encoding is used.
 *    Function Signature of execute function:
 *           function execute(ModeCode mode, bytes calldata executionCalldata) external payable;
 * This allows for a single bytes32 to be used to encode the execution mode, calltype, execType and
 * context.
 * NOTE: Simple Account implementations only have to scope for the most significant byte. Account  that
 * implement
 * more complex execution modes may use the entire bytes32.
 *
 * |--------------------------------------------------------------------|
 * | CALLTYPE  | EXECTYPE  |   UNUSED   | ModeSelector  |  ModePayload  |
 * |--------------------------------------------------------------------|
 * | 1 byte    | 1 byte    |   4 bytes  | 4 bytes       |   22 bytes    |
 * |--------------------------------------------------------------------|
 *
 * CALLTYPE: 1 byte
 * CallType is used to determine how the executeCalldata paramter of the execute function has to be
 * decoded.
 * It can be either single, batch or delegatecall. In the future different calls could be added.
 * CALLTYPE can be used by a validation module to determine how to decode <userOp.callData[36:]>.
 *
 * EXECTYPE: 1 byte
 * ExecType is used to determine how the account should handle the execution.
 * It can indicate if the execution should revert on failure or continue execution.
 * In the future more execution modes may be added.
 * Default Behavior (EXECTYPE = 0x00) is to revert on a single failed execution. If one execution in
 * a batch fails, the entire batch is reverted
 *
 * UNUSED: 4 bytes
 * Unused bytes are reserved for future use.
 *
 * ModeSelector: bytes4
 * The "optional" mode selector can be used by account vendors, to implement custom behavior in
 * their accounts.
 * the way a ModeSelector is to be calculated is bytes4(keccak256("vendorname.featurename"))
 * this is to prevent collisions between different vendors, while allowing innovation and the
 * development of new features without coordination between ERC-7579 implementing accounts
 *
 * ModePayload: 22 bytes
 * Mode payload is used to pass additional data to the smart account execution, this may be
 * interpreted depending on the ModeSelector
 *
 * ExecutionCallData: n bytes
 * single, delegatecall or batch exec abi.encoded as bytes
 */

// Custom type for improved developer experience
type ModeCode is bytes32;

type CallType is bytes1;

type ExecType is bytes1;

type ModeSelector is bytes4;

type ModePayload is bytes22;

// Default CallType
CallType constant CALLTYPE_SINGLE = CallType.wrap(0x00);
// Batched CallType
CallType constant CALLTYPE_BATCH = CallType.wrap(0x01);
CallType constant CALLTYPE_STATIC = CallType.wrap(0xFE);
// @dev Implementing delegatecall is OPTIONAL!
// implement delegatecall with extreme care.
CallType constant CALLTYPE_DELEGATECALL = CallType.wrap(0xFF);

// @dev default behavior is to revert on failure
// To allow very simple accounts to use mode encoding, the default behavior is to revert on failure
// Since this is value 0x00, no additional encoding is required for simple accounts
ExecType constant EXECTYPE_DEFAULT = ExecType.wrap(0x00);
// @dev account may elect to change execution behavior. For example "try exec" / "allow fail"
ExecType constant EXECTYPE_TRY = ExecType.wrap(0x01);

ModeSelector constant MODE_DEFAULT = ModeSelector.wrap(bytes4(0x00000000));
// Example declaration of a custom mode selector
ModeSelector constant MODE_OFFSET = ModeSelector.wrap(bytes4(keccak256("default.mode.offset")));

/**
 * @dev ModeLib is a helper library to encode/decode ModeCodes
 */
library ModeLib {
    function decode(ModeCode mode)
        internal
        pure
        returns (CallType _calltype, ExecType _execType, ModeSelector _modeSelector, ModePayload _modePayload)
    {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            _calltype := mode
            _execType := shl(8, mode)
            _modeSelector := shl(48, mode)
            _modePayload := shl(80, mode)
        }
    }

    function encode(
        CallType callType,
        ExecType execType,
        ModeSelector mode,
        ModePayload payload
    )
        internal
        pure
        returns (ModeCode)
    {
        return
            ModeCode.wrap(bytes32(abi.encodePacked(callType, execType, bytes4(0), ModeSelector.unwrap(mode), payload)));
    }

    function encodeSimpleBatch() internal pure returns (ModeCode mode) {
        mode = encode(CALLTYPE_BATCH, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00));
    }

    function encodeSimpleSingle() internal pure returns (ModeCode mode) {
        mode = encode(CALLTYPE_SINGLE, EXECTYPE_DEFAULT, MODE_DEFAULT, ModePayload.wrap(0x00));
    }

    function getCallType(ModeCode mode) internal pure returns (CallType calltype) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            calltype := mode
        }
    }
}

using { eqModeSelector as == } for ModeSelector global;
using { eqCallType as == } for CallType global;
using { neqCallType as != } for CallType global;
using { eqExecType as == } for ExecType global;

function eqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) == CallType.unwrap(b);
}

function neqCallType(CallType a, CallType b) pure returns (bool) {
    return CallType.unwrap(a) == CallType.unwrap(b);
}

function eqExecType(ExecType a, ExecType b) pure returns (bool) {
    return ExecType.unwrap(a) == ExecType.unwrap(b);
}

function eqModeSelector(ModeSelector a, ModeSelector b) pure returns (bool) {
    return ModeSelector.unwrap(a) == ModeSelector.unwrap(b);
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/PackedUserOperation.sol

/**
 * User Operation struct
 * @param sender                - The sender account of this request.
 * @param nonce                 - Unique value the sender uses to verify it is not a replay.
 * @param initCode              - If set, the account contract will be created by this constructor/
 * @param callData              - The method call to execute on this account.
 * @param accountGasLimits      - Packed gas limits for validateUserOp and gas limit passed to the callData method call.
 * @param preVerificationGas    - Gas not calculated by the handleOps method, but added to the gas paid.
 *                                Covers batch overhead.
 * @param gasFees               - packed gas fields maxPriorityFeePerGas and maxFeePerGas - Same as EIP-1559 gas
 * parameters.
 * @param paymasterAndData      - If set, this field holds the paymaster address, verification gas limit, postOp gas
 * limit and paymaster-specific extra data
 *                                The paymaster will pay for the transaction instead of the sender.
 * @param signature             - Sender-verified signature over the entire request, the EntryPoint address and the
 * chain ID.
 */
struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

// node_modules/@openzeppelin/contracts/utils/ReentrancyGuard.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/ReentrancyGuard.sol)

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If EIP-1153 (transient storage) is available on the chain you're deploying at,
 * consider using {ReentrancyGuardTransient} instead.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant NOT_ENTERED = 1;
    uint256 private constant ENTERED = 2;

    uint256 private _status;

    /**
     * @dev Unauthorized reentrant call.
     */
    error ReentrancyGuardReentrantCall();

    constructor() {
        _status = NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and making it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        // On the first call to nonReentrant, _status will be NOT_ENTERED
        if (_status == ENTERED) {
            revert ReentrancyGuardReentrantCall();
        }

        // Any calls to nonReentrant after this point will fail
        _status = ENTERED;
    }

    function _nonReentrantAfter() private {
        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = NOT_ENTERED;
    }

    /**
     * @dev Returns true if the reentrancy guard is currently set to "entered", which indicates there is a
     * `nonReentrant` function in the call stack.
     */
    function _reentrancyGuardEntered() internal view returns (bool) {
        return _status == ENTERED;
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/SenderCreator.sol

/**
 * Helper contract for EntryPoint, to call userOp.initCode from a "neutral" address,
 * which is explicitly not the entryPoint itself.
 */
contract SenderCreator {
    /**
     * Call the "initCode" factory to create and return the sender account address.
     * @param initCode - The initCode value from a UserOp. contains 20 bytes of factory address,
     *                   followed by calldata.
     * @return sender  - The returned address of the created account, or zero address on failure.
     */
    function createSender(bytes calldata initCode) external returns (address sender) {
        address factory = address(bytes20(initCode[0:20]));
        bytes memory initCallData = initCode[20:];
        bool success;
        /* solhint-disable no-inline-assembly */
        assembly ("memory-safe") {
            success := call(gas(), factory, 0, add(initCallData, 0x20), mload(initCallData), 0, 32)
            sender := mload(0)
        }
        if (!success) {
            sender = address(0);
        }
    }
}

// node_modules/@rhinestone/sentinellist/src/SentinelList4337.sol

// Sentinel address
address constant SENTINEL = address(0x1);
// Zero address
address constant ZERO_ADDRESS = address(0x0);

/**
 * @title SentinelListLib
 * @dev Library for managing a linked list of addresses that is compliant with the ERC-4337
 * validation rules
 * @author Rhinestone
 */
library SentinelList4337Lib {
    // Struct to hold the linked list
    // This linked list has the account address as the inner key so it is ERC-4337 compliant
    struct SentinelList {
        mapping(address key => mapping(address account => address entry)) entries;
    }

    error LinkedList_AlreadyInitialized();
    error LinkedList_InvalidPage();
    error LinkedList_InvalidEntry(address entry);
    error LinkedList_EntryAlreadyInList(address entry);

    /**
     * Initialize the linked list
     *
     * @param self The linked list
     * @param account The account to initialize the linked list for
     */
    function init(SentinelList storage self, address account) internal {
        if (alreadyInitialized(self, account)) revert LinkedList_AlreadyInitialized();
        self.entries[SENTINEL][account] = SENTINEL;
    }

    /**
     * Check if the linked list is already initialized
     *
     * @param self The linked list
     * @param account The account to check if the linked list is initialized for
     *
     * @return bool True if the linked list is already initialized
     */
    function alreadyInitialized(SentinelList storage self, address account) internal view returns (bool) {
        return self.entries[SENTINEL][account] != ZERO_ADDRESS;
    }

    /**
     * Get the next entry in the linked list
     *
     * @param self The linked list
     * @param account The account to get the next entry for
     * @param entry The current entry
     *
     * @return address The next entry
     */
    function getNext(SentinelList storage self, address account, address entry) internal view returns (address) {
        if (entry == ZERO_ADDRESS) {
            revert LinkedList_InvalidEntry(entry);
        }
        return self.entries[entry][account];
    }

    /**
     * Push a new entry to the linked list
     *
     * @param self The linked list
     * @param account The account to push the new entry for
     * @param newEntry The new entry
     */
    function push(SentinelList storage self, address account, address newEntry) internal {
        if (newEntry == ZERO_ADDRESS || newEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(newEntry);
        }
        if (self.entries[newEntry][account] != ZERO_ADDRESS) {
            revert LinkedList_EntryAlreadyInList(newEntry);
        }
        self.entries[newEntry][account] = self.entries[SENTINEL][account];
        self.entries[SENTINEL][account] = newEntry;
    }

    /**
     * Safe push a new entry to the linked list
     * @dev This ensures that the linked list is initialized and initializes it if it is not
     *
     * @param self The linked list
     * @param account The account to push the new entry for
     * @param newEntry The new entry
     */
    function safePush(SentinelList storage self, address account, address newEntry) internal {
        if (!alreadyInitialized(self, account)) {
            init({ self: self, account: account });
        }
        push({ self: self, account: account, newEntry: newEntry });
    }

    /**
     * Pop an entry from the linked list
     *
     * @param self The linked list
     * @param account The account to pop the entry for
     * @param prevEntry The entry before the entry to pop
     * @param popEntry The entry to pop
     */
    function pop(SentinelList storage self, address account, address prevEntry, address popEntry) internal {
        if (popEntry == ZERO_ADDRESS || popEntry == SENTINEL) {
            revert LinkedList_InvalidEntry(prevEntry);
        }
        if (self.entries[prevEntry][account] != popEntry) {
            revert LinkedList_InvalidEntry(popEntry);
        }
        self.entries[prevEntry][account] = self.entries[popEntry][account];
        self.entries[popEntry][account] = ZERO_ADDRESS;
    }

    /**
     * Pop all entries from the linked list
     *
     * @param self The linked list
     * @param account The account to pop all entries for
     */
    function popAll(SentinelList storage self, address account) internal {
        address next = self.entries[SENTINEL][account];
        while (next != ZERO_ADDRESS) {
            address current = next;
            next = self.entries[next][account];
            self.entries[current][account] = ZERO_ADDRESS;
        }
    }

    /**
     * Check if the linked list contains an entry
     *
     * @param self The linked list
     * @param account The account to check if the entry is in the linked list for
     * @param entry The entry to check for
     *
     * @return bool True if the linked list contains the entry
     */
    function contains(SentinelList storage self, address account, address entry) internal view returns (bool) {
        return SENTINEL != entry && self.entries[entry][account] != ZERO_ADDRESS;
    }

    /**
     * Get all entries in the linked list
     *
     * @param self The linked list
     * @param account The account to get the entries for
     * @param start The start entry
     * @param pageSize The page size
     *
     * @return array All entries in the linked list
     * @return next The next entry
     */
    function getEntriesPaginated(
        SentinelList storage self,
        address account,
        address start,
        uint256 pageSize
    )
        internal
        view
        returns (address[] memory array, address next)
    {
        if (start != SENTINEL && !contains(self, account, start)) {
            revert LinkedList_InvalidEntry(start);
        }
        if (pageSize == 0) revert LinkedList_InvalidPage();
        // Init array with max page size
        array = new address[](pageSize);

        // Populate return array
        uint256 entryCount = 0;
        next = self.entries[start][account];
        while (next != ZERO_ADDRESS && next != SENTINEL && entryCount < pageSize) {
            array[entryCount] = next;
            next = self.entries[next][account];
            entryCount++;
        }

        /**
         * Because of the argument validation, we can assume that the loop will always iterate over
         * the valid entry list values
         *       and the `next` variable will either be an enabled entry or a sentinel address
         * (signalling the end).
         *
         *       If we haven't reached the end inside the loop, we need to set the next pointer to
         * the last element of the entry array
         *       because the `next` variable (which is a entry by itself) acting as a pointer to the
         * start of the next page is neither
         *       incSENTINELrent page, nor will it be included in the next one if you pass it as a
         * start.
         */
        if (next != SENTINEL && entryCount > 0) {
            next = array[entryCount - 1];
        }
        // Set correct size of returned array
        // solhint-disable-next-line no-inline-assembly
        /// @solidity memory-safe-assembly
        assembly {
            mstore(array, entryCount)
        }
    }
}

// node_modules/solady/src/utils/SignatureCheckerLib.sol

/// @notice Signature verification helper that supports both ECDSA signatures from EOAs
/// and ERC1271 signatures from smart contract wallets like Argent and Gnosis safe.
/// @author Solady (https://github.com/vectorized/solady/blob/main/src/utils/SignatureCheckerLib.sol)
/// @author Modified from OpenZeppelin
/// (https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/cryptography/SignatureChecker.sol)
///
/// @dev Note:
/// - The signature checking functions use the ecrecover precompile (0x1).
/// - The `bytes memory signature` variants use the identity precompile (0x4)
///   to copy memory internally.
/// - Unlike ECDSA signatures, contract signatures are revocable.
/// - As of Solady version 0.0.134, all `bytes signature` variants accept both
///   regular 65-byte `(r, s, v)` and EIP-2098 `(r, vs)` short form signatures.
///   See: https://eips.ethereum.org/EIPS/eip-2098
///   This is for calldata efficiency on smart accounts prevalent on L2s.
///
/// WARNING! Do NOT use signatures as unique identifiers:
/// - Use a nonce in the digest to prevent replay attacks on the same contract.
/// - Use EIP-712 for the digest to prevent replay attacks across different chains and contracts.
///   EIP-712 also enables readable signing of typed data for better user safety.
/// This implementation does NOT check if a signature is non-malleable.
library SignatureCheckerLib {
    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*               SIGNATURE CHECKING OPERATIONS                */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    )
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            for { } 1 { } {
                if iszero(extcodesize(signer)) {
                    switch mload(signature)
                    case 64 {
                        let vs := mload(add(signature, 0x40))
                        mstore(0x20, add(shr(255, vs), 27)) // `v`.
                        mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    }
                    case 65 {
                        mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                        mstore(0x60, mload(add(signature, 0x40))) // `s`.
                    }
                    default { break }
                    mstore(0x00, hash)
                    mstore(0x40, mload(add(signature, 0x20))) // `r`.
                    let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                    isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                // Copy the `signature` over.
                let n := add(0x20, mload(signature))
                let copied := staticcall(gas(), 4, signature, n, add(m, 0x44), n)
                isValid := staticcall(gas(), signer, m, add(returndatasize(), 0x44), d, 0x20)
                isValid := and(eq(mload(d), f), and(isValid, copied))
                break
            }
        }
    }

    /// @dev Returns whether `signature` is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            for { } 1 { } {
                if iszero(extcodesize(signer)) {
                    switch signature.length
                    case 64 {
                        let vs := calldataload(add(signature.offset, 0x20))
                        mstore(0x20, add(shr(255, vs), 27)) // `v`.
                        mstore(0x40, calldataload(signature.offset)) // `r`.
                        mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    }
                    case 65 {
                        mstore(0x20, byte(0, calldataload(add(signature.offset, 0x40)))) // `v`.
                        calldatacopy(0x40, signature.offset, 0x40) // `r`, `s`.
                    }
                    default { break }
                    mstore(0x00, hash)
                    let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                    isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), signature.length)
                // Copy the `signature` over.
                calldatacopy(add(m, 0x64), signature.offset, signature.length)
                isValid := staticcall(gas(), signer, m, add(signature.length, 0x64), d, 0x20)
                isValid := and(eq(mload(d), f), isValid)
                break
            }
        }
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    )
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            for { } 1 { } {
                if iszero(extcodesize(signer)) {
                    mstore(0x00, hash)
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x40, r) // `r`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                    let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                    isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), 65) // Length of the signature.
                mstore(add(m, 0x64), r) // `r`.
                mstore(add(m, 0x84), shr(1, shl(1, vs))) // `s`.
                mstore8(add(m, 0xa4), add(shr(255, vs), 27)) // `v`.
                isValid := staticcall(gas(), signer, m, 0xa5, d, 0x20)
                isValid := and(eq(mload(d), f), isValid)
                break
            }
        }
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `signer` and `hash`.
    /// If `signer.code.length == 0`, then validate with `ecrecover`, else
    /// it will validate with ERC1271 on `signer`.
    function isValidSignatureNow(
        address signer,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        internal
        view
        returns (bool isValid)
    {
        if (signer == address(0)) return isValid;
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            for { } 1 { } {
                if iszero(extcodesize(signer)) {
                    mstore(0x00, hash)
                    mstore(0x20, and(v, 0xff)) // `v`.
                    mstore(0x40, r) // `r`.
                    mstore(0x60, s) // `s`.
                    let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                    isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                    mstore(0x60, 0) // Restore the zero slot.
                    mstore(0x40, m) // Restore the free memory pointer.
                    break
                }
                let f := shl(224, 0x1626ba7e)
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                let d := add(m, 0x24)
                mstore(d, 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), 65) // Length of the signature.
                mstore(add(m, 0x64), r) // `r`.
                mstore(add(m, 0x84), s) // `s`.
                mstore8(add(m, 0xa4), v) // `v`.
                isValid := staticcall(gas(), signer, m, 0xa5, d, 0x20)
                isValid := and(eq(mload(d), f), isValid)
                break
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC1271 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: These ERC1271 operations do NOT have an ECDSA fallback.

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    )
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            // Copy the `signature` over.
            let n := add(0x20, mload(signature))
            let copied := staticcall(gas(), 4, signature, n, add(m, 0x44), n)
            isValid := staticcall(gas(), signer, m, add(returndatasize(), 0x44), d, 0x20)
            isValid := and(eq(mload(d), f), and(isValid, copied))
        }
    }

    /// @dev Returns whether `signature` is valid for `hash` for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNowCalldata(
        address signer,
        bytes32 hash,
        bytes calldata signature
    )
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), signature.length)
            // Copy the `signature` over.
            calldatacopy(add(m, 0x64), signature.offset, signature.length)
            isValid := staticcall(gas(), signer, m, add(signature.length, 0x64), d, 0x20)
            isValid := and(eq(mload(d), f), isValid)
        }
    }

    /// @dev Returns whether the signature (`r`, `vs`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(
        address signer,
        bytes32 hash,
        bytes32 r,
        bytes32 vs
    )
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), 65) // Length of the signature.
            mstore(add(m, 0x64), r) // `r`.
            mstore(add(m, 0x84), shr(1, shl(1, vs))) // `s`.
            mstore8(add(m, 0xa4), add(shr(255, vs), 27)) // `v`.
            isValid := staticcall(gas(), signer, m, 0xa5, d, 0x20)
            isValid := and(eq(mload(d), f), isValid)
        }
    }

    /// @dev Returns whether the signature (`v`, `r`, `s`) is valid for `hash`
    /// for an ERC1271 `signer` contract.
    function isValidERC1271SignatureNow(
        address signer,
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    )
        internal
        view
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let m := mload(0x40)
            let f := shl(224, 0x1626ba7e)
            mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
            mstore(add(m, 0x04), hash)
            let d := add(m, 0x24)
            mstore(d, 0x40) // The offset of the `signature` in the calldata.
            mstore(add(m, 0x44), 65) // Length of the signature.
            mstore(add(m, 0x64), r) // `r`.
            mstore(add(m, 0x84), s) // `s`.
            mstore8(add(m, 0xa4), v) // `v`.
            isValid := staticcall(gas(), signer, m, 0xa5, d, 0x20)
            isValid := and(eq(mload(d), f), isValid)
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     ERC6492 OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    // Note: These ERC6492 operations now include an ECDSA fallback at the very end.
    // The calldata variants are excluded for brevity.

    /// @dev Returns whether `signature` is valid for `hash`.
    /// If the signature is postfixed with the ERC6492 magic number, it will attempt to
    /// deploy / prepare the `signer` smart account before doing a regular ERC1271 check.
    /// Note: This function is NOT reentrancy safe.
    /// The verifier must be deployed.
    /// Otherwise, the function will return false if `signer` is not yet deployed / prepared.
    /// See: https://gist.github.com/Vectorized/011d6becff6e0a73e42fe100f8d7ef04
    /// With a dedicated verifier, this function is safe to use in contracts
    /// that have been granted special permissions.
    function isValidERC6492SignatureNowAllowSideEffects(
        address signer,
        bytes32 hash,
        bytes memory signature
    )
        internal
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            function callIsValidSignature(signer_, hash_, signature_) -> _isValid {
                let m_ := mload(0x40)
                let f_ := shl(224, 0x1626ba7e)
                mstore(m_, f_) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m_, 0x04), hash_)
                let d_ := add(m_, 0x24)
                mstore(d_, 0x40) // The offset of the `signature` in the calldata.
                let n_ := add(0x20, mload(signature_))
                let copied_ := staticcall(gas(), 4, signature_, n_, add(m_, 0x44), n_)
                _isValid := staticcall(gas(), signer_, m_, add(returndatasize(), 0x44), d_, 0x20)
                _isValid := and(eq(mload(d_), f_), and(_isValid, copied_))
            }
            let noCode := iszero(extcodesize(signer))
            let n := mload(signature)
            for { } 1 { } {
                if iszero(eq(mload(add(signature, n)), mul(0x6492, div(not(isValid), 0xffff)))) {
                    if iszero(noCode) { isValid := callIsValidSignature(signer, hash, signature) }
                    break
                }
                if iszero(noCode) {
                    let o := add(signature, 0x20) // Signature bytes.
                    isValid := callIsValidSignature(signer, hash, add(o, mload(add(o, 0x40))))
                    if isValid { break }
                }
                let m := mload(0x40)
                mstore(m, signer)
                mstore(add(m, 0x20), hash)
                pop(
                    call(
                        gas(), // Remaining gas.
                        0x0000bc370E4DC924F427d84e2f4B9Ec81626ba7E, // Non-reverting verifier.
                        0, // Send zero ETH.
                        m, // Start of memory.
                        add(returndatasize(), 0x40), // Length of calldata in memory.
                        staticcall(gas(), 4, add(signature, 0x20), n, add(m, 0x40), n), // 1.
                        0x00 // Length of returndata to write.
                    )
                )
                isValid := returndatasize()
                break
            }
            // Do `ecrecover` fallback if `noCode && !isValid`.
            for { } gt(noCode, isValid) { } {
                switch n
                case 64 {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                    mstore(0x60, mload(add(signature, 0x40))) // `s`.
                }
                default { break }
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) // `r`.
                let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /// @dev Returns whether `signature` is valid for `hash`.
    /// If the signature is postfixed with the ERC6492 magic number, it will attempt
    /// to use a reverting verifier to deploy / prepare the `signer` smart account
    /// and do a `isValidSignature` check via the reverting verifier.
    /// Note: This function is reentrancy safe.
    /// The reverting verifier must be deployed.
    /// Otherwise, the function will return false if `signer` is not yet deployed / prepared.
    /// See: https://gist.github.com/Vectorized/846a474c855eee9e441506676800a9ad
    function isValidERC6492SignatureNow(
        address signer,
        bytes32 hash,
        bytes memory signature
    )
        internal
        returns (bool isValid)
    {
        /// @solidity memory-safe-assembly
        assembly {
            function callIsValidSignature(signer_, hash_, signature_) -> _isValid {
                let m_ := mload(0x40)
                let f_ := shl(224, 0x1626ba7e)
                mstore(m_, f_) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m_, 0x04), hash_)
                let d_ := add(m_, 0x24)
                mstore(d_, 0x40) // The offset of the `signature` in the calldata.
                let n_ := add(0x20, mload(signature_))
                let copied_ := staticcall(gas(), 4, signature_, n_, add(m_, 0x44), n_)
                _isValid := staticcall(gas(), signer_, m_, add(returndatasize(), 0x44), d_, 0x20)
                _isValid := and(eq(mload(d_), f_), and(_isValid, copied_))
            }
            let noCode := iszero(extcodesize(signer))
            let n := mload(signature)
            for { } 1 { } {
                if iszero(eq(mload(add(signature, n)), mul(0x6492, div(not(isValid), 0xffff)))) {
                    if iszero(noCode) { isValid := callIsValidSignature(signer, hash, signature) }
                    break
                }
                if iszero(noCode) {
                    let o := add(signature, 0x20) // Signature bytes.
                    isValid := callIsValidSignature(signer, hash, add(o, mload(add(o, 0x40))))
                    if isValid { break }
                }
                let m := mload(0x40)
                mstore(m, signer)
                mstore(add(m, 0x20), hash)
                let willBeZeroIfRevertingVerifierExists :=
                    call(
                        gas(), // Remaining gas.
                        0x00007bd799e4A591FeA53f8A8a3E9f931626Ba7e, // Reverting verifier.
                        0, // Send zero ETH.
                        m, // Start of memory.
                        add(returndatasize(), 0x40), // Length of calldata in memory.
                        staticcall(gas(), 4, add(signature, 0x20), n, add(m, 0x40), n), // 1.
                        0x00 // Length of returndata to write.
                    )
                isValid := gt(returndatasize(), willBeZeroIfRevertingVerifierExists)
                break
            }
            // Do `ecrecover` fallback if `noCode && !isValid`.
            for { } gt(noCode, isValid) { } {
                switch n
                case 64 {
                    let vs := mload(add(signature, 0x40))
                    mstore(0x20, add(shr(255, vs), 27)) // `v`.
                    mstore(0x60, shr(1, shl(1, vs))) // `s`.
                }
                case 65 {
                    mstore(0x20, byte(0, mload(add(signature, 0x60)))) // `v`.
                    mstore(0x60, mload(add(signature, 0x40))) // `s`.
                }
                default { break }
                let m := mload(0x40)
                mstore(0x00, hash)
                mstore(0x40, mload(add(signature, 0x20))) // `r`.
                let recovered := mload(staticcall(gas(), 1, 0x00, 0x80, 0x01, 0x20))
                isValid := gt(returndatasize(), shl(96, xor(signer, recovered)))
                mstore(0x60, 0) // Restore the zero slot.
                mstore(0x40, m) // Restore the free memory pointer.
                break
            }
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                     HASHING OPERATIONS                     */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an Ethereum Signed Message, created from a `hash`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x20, hash) // Store into scratch space for keccak256.
            mstore(0x00, "\x00\x00\x00\x00\x19Ethereum Signed Message:\n32") // 28 bytes.
            result := keccak256(0x04, 0x3c) // `32 * 2 - (32 - 28) = 60 = 0x3c`.
        }
    }

    /// @dev Returns an Ethereum Signed Message, created from `s`.
    /// This produces a hash corresponding to the one signed with the
    /// [`eth_sign`](https://eth.wiki/json-rpc/API#eth_sign)
    /// JSON-RPC method as part of EIP-191.
    /// Note: Supports lengths of `s` up to 999999 bytes.
    function toEthSignedMessageHash(bytes memory s) internal pure returns (bytes32 result) {
        /// @solidity memory-safe-assembly
        assembly {
            let sLength := mload(s)
            let o := 0x20
            mstore(o, "\x19Ethereum Signed Message:\n") // 26 bytes, zero-right-padded.
            mstore(0x00, 0x00)
            // Convert the `s.length` to ASCII decimal representation: `base10(s.length)`.
            for { let temp := sLength } 1 { } {
                o := sub(o, 1)
                mstore8(o, add(48, mod(temp, 10)))
                temp := div(temp, 10)
                if iszero(temp) { break }
            }
            let n := sub(0x3a, o) // Header length: `26 + 32 - o`.
            // Throw an out-of-offset error (consumes all gas) if the header exceeds 32 bytes.
            returndatacopy(returndatasize(), returndatasize(), gt(n, 0x20))
            mstore(s, or(mload(0x00), mload(n))) // Temporarily store the header.
            result := keccak256(add(s, sub(0x20, n)), add(n, sLength))
            mstore(s, sLength) // Restore the length.
        }
    }

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                   EMPTY CALLDATA HELPERS                   */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /// @dev Returns an empty calldata bytes.
    function emptySignature() internal pure returns (bytes calldata signature) {
        /// @solidity memory-safe-assembly
        assembly {
            signature.length := 0
        }
    }
}

// node_modules/@rhinestone/modulekit/src/module-bases/utils/TrustedForwarder.sol

abstract contract TrustedForwarder {
    // account => trustedForwarder
    mapping(address account => address trustedForwarder) public trustedForwarder;

    /**
     * Set the trusted forwarder for an account
     *
     * @param forwarder The address of the trusted forwarder
     */
    function setTrustedForwarder(address forwarder) external {
        trustedForwarder[msg.sender] = forwarder;
    }

    /**
     * Clear the trusted forwarder for an account
     */
    function clearTrustedForwarder() public {
        trustedForwarder[msg.sender] = address(0);
    }

    /**
     * Check if a forwarder is trusted for an account
     *
     * @param forwarder The address of the forwarder
     * @param account The address of the account
     *
     * @return true if the forwarder is trusted for the account
     */
    function isTrustedForwarder(address forwarder, address account) public view returns (bool) {
        return forwarder == trustedForwarder[account];
    }

    /**
     * Get the sender of the transaction
     *
     * @return account the sender of the transaction
     */
    function _getAccount() internal view returns (address account) {
        account = msg.sender;
        address _account;
        address forwarder;
        if (msg.data.length >= 40) {
            // solhint-disable-next-line no-inline-assembly
            assembly {
                _account := shr(96, calldataload(sub(calldatasize(), 20)))
                forwarder := shr(96, calldataload(sub(calldatasize(), 40)))
            }
            if (forwarder == msg.sender && isTrustedForwarder(forwarder, _account)) {
                account = _account;
            }
        }
    }
}

// node_modules/@rhinestone/checknsignatures/src/CheckNSignatures.sol

// EIP1271 magic value
bytes4 constant EIP1271_MAGIC_VALUE = 0x1626ba7e;

error InvalidSignature();
error WrongContractSignatureFormat(uint256 s, uint256 contractSignatureLen, uint256 signaturesLen);
error WrongContractSignature(bytes contractSignature);
error WrongSignature(bytes signature);

/**
 * @title CheckSignatures
 * @dev Library for recovering n signatures
 * @author Rhinestone
 * @notice This library is based on the Gnosis Safe signature recovery library
 */
library CheckSignatures {
    /**
     * Recover n signatures from a data hash
     *
     * @param dataHash The hash of the data
     * @param signatures The concatenated signatures
     * @param requiredSignatures The number of signatures required
     *
     * @return recoveredSigners The recovered signers
     */
    function recoverNSignatures(
        bytes32 dataHash,
        bytes memory signatures,
        uint256 requiredSignatures
    )
        internal
        view
        returns (address[] memory recoveredSigners)
    {
        uint256 signaturesLength = signatures.length;
        uint256 totalSignatures = signaturesLength / 65;
        recoveredSigners = new address[](totalSignatures);
        if (totalSignatures < requiredSignatures) revert InvalidSignature();
        uint256 validSigCount;
        for (uint256 i; i < totalSignatures; i++) {
            // split v,r,s from signatures
            address _signer;
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit({ signatures: signatures, pos: i });

            if (v == 0) {
                // If v is 0 then it is a contract signature
                _signer = isValidContractSignature(dataHash, signatures, r, s, signaturesLength);
            } else if (v > 30) {
                // If v > 30 then default va (27,28) has been adjusted for eth_sign flow
                // To support eth_sign and similar we adjust v and hash the messageHash with the
                // Ethereum message prefix before applying ecrecover
                _signer = ECDSA.tryRecover({ hash: ECDSA.toEthSignedMessageHash(dataHash), v: v - 4, r: r, s: s });
            } else {
                _signer = ECDSA.tryRecover({ hash: dataHash, v: v, r: r, s: s });
            }
            if (_signer != address(0)) {
                validSigCount++;
            }
            recoveredSigners[i] = _signer;
        }
        if (validSigCount < requiredSignatures) revert InvalidSignature();
    }

    /**
     * @notice Validates a contract signature following the ERC-1271 standard
     * @param dataHash Hash of the data that has been signed
     * @param signatures The concatenated signatures
     * @param r Signature r value
     * @param s Signature s value
     * @param signaturesLength The length of the signatures
     */
    function isValidContractSignature(
        bytes32 dataHash,
        bytes memory signatures,
        bytes32 r,
        bytes32 s,
        uint256 signaturesLength
    )
        internal
        view
        returns (address _signer)
    {
        // When handling contract signatures the address of the signer contract is encoded
        // into r
        _signer = address(uint160(uint256(r)));

        // Check if the contract signature is in bounds: start of data is s + 32 and end is
        // start + signature length
        uint256 contractSignatureLen;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            contractSignatureLen := mload(add(add(signatures, s), 0x20))
        }

        // Check if the contract signature is in bounds
        if (contractSignatureLen + uint256(s) + 32 > signaturesLength) {
            return address(0);
        }

        // Check signature
        bytes memory contractSignature;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // The signature data for contract signatures is appended to the concatenated
            // signatures and the offset is stored in s
            contractSignature := add(add(signatures, s), 0x20)
        }
        if (ISignatureValidator(_signer).isValidSignature(dataHash, contractSignature) != EIP1271_MAGIC_VALUE) {
            return address(0);
        }
    }

    /**
     * @notice Splits signature bytes into `uint8 v, bytes32 r, bytes32 s`.
     * @dev Make sure to perform a bounds check for @param pos, to avoid out of bounds access on
     * @param signatures The signature format is a compact form of {bytes32 r}{bytes32 s}{uint8 v}
     * Compact means uint8 is not padded to 32 bytes.
     * @param pos Which signature to read. A prior bounds check of this parameter should be
     * performed, to avoid out of bounds access.
     * @param signatures Concatenated {r, s, v} signatures.
     * @return v Recovery ID or Safe signature type.
     * @return r Output value r of the signature.
     * @return s Output value s of the signature.
     *
     * @ author Gnosis Team /rmeissner
     */
    function signatureSplit(
        bytes memory signatures,
        uint256 pos
    )
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        // solhint-disable-next-line no-inline-assembly
        /// @solidity memory-safe-assembly
        assembly {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := byte(0, mload(add(signatures, add(signaturePos, 0x60))))
        }
    }
}

abstract contract ISignatureValidator {
    /**
     * @dev Should return whether the signature provided is valid for the provided data
     * @param _dataHash Arbitrary length data signed on behalf of address(this)
     * @param _signature Signature byte array associated with _data
     *
     * MUST return the bytes4 magic value when function passes.
     * MUST NOT modify state (using STATICCALL for solc < 0.5, view modifier for solc > 0.5)
     * MUST allow external calls
     */
    function isValidSignature(bytes32 _dataHash, bytes memory _signature) public view virtual returns (bytes4);
}

// node_modules/@openzeppelin/contracts/utils/introspection/ERC165.sol

// OpenZeppelin Contracts (last updated v5.1.0) (utils/introspection/ERC165.sol)

/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC-165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 */
abstract contract ERC165 is IERC165_0 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual returns (bool) {
        return interfaceId == type(IERC165_0).interfaceId;
    }
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7484RegistryAdapter.sol

abstract contract ERC7484RegistryAdapter {
    // registry address
    IERC7484 public immutable REGISTRY;

    /**
     * Contract constructor
     * @dev sets the registry as an immutable variable
     *
     * @param _registry The registry address
     */
    constructor(IERC7484 _registry) {
        // set the registry
        REGISTRY = _registry;
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IAccount.sol

interface IAccount {
    /**
     * Validate user's signature and nonce
     * the entryPoint will make the call to the recipient only if this validation call returns successfully.
     * signature failure should be reported by returning SIG_VALIDATION_FAILED (1).
     * This allows making a "simulation call" without a valid signature
     * Other failures (e.g. nonce mismatch, or invalid signature format) should still revert to signal failure.
     *
     * @dev Must validate caller is the entryPoint.
     *      Must validate the signature and nonce
     * @param userOp              - The operation that is about to be executed.
     * @param userOpHash          - Hash of the user's request data. can be used as the basis for signature.
     * @param missingAccountFunds - Missing funds on the account's deposit in the entrypoint.
     *                              This is the minimum amount to transfer to the sender(entryPoint) to be
     *                              able to make the call. The excess is left as a deposit in the entrypoint
     *                              for future calls. Can be withdrawn anytime using "entryPoint.withdrawTo()".
     *                              In case there is a paymaster in the request (or the current deposit is high
     *                              enough), this value will be zero.
     * @return validationData       - Packaged ValidationData structure. use `_packValidationData` and
     *                              `_unpackValidationData` to encode and decode.
     *                              <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *                                 otherwise, an address of an "authorizer" contract.
     *                              <6-byte> validUntil - Last timestamp this operation is valid. 0 for "indefinite"
     *                              <6-byte> validAfter - First timestamp this operation is valid
     *                                                    If an account doesn't use time-range, it is enough to
     *                                                    return SIG_VALIDATION_FAILED value (1) for signature failure.
     *                              Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    )
        external
        returns (uint256 validationData);
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IAccountExecute.sol

interface IAccountExecute {
    /**
     * Account may implement this execute method.
     * passing this methodSig at the beginning of callData will cause the entryPoint to pass the full UserOp (and hash)
     * to the account.
     * The account should skip the methodSig, and use the callData (and optionally, other UserOp fields)
     *
     * @param userOp              - The operation that was just validated.
     * @param userOpHash          - Hash of the user's request data.
     */
    function executeUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash) external;
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IAggregator.sol

/**
 * Aggregated Signatures validator.
 */
interface IAggregator {
    /**
     * Validate aggregated signature.
     * Revert if the aggregated signature does not match the given list of operations.
     * @param userOps   - Array of UserOperations to validate the signature for.
     * @param signature - The aggregated signature.
     */
    function validateSignatures(PackedUserOperation[] calldata userOps, bytes calldata signature) external view;

    /**
     * Validate signature of a single userOp.
     * This method should be called by bundler after EntryPointSimulation.simulateValidation() returns
     * the aggregator this account uses.
     * First it validates the signature over the userOp. Then it returns data to be used when creating the handleOps.
     * @param userOp        - The userOperation received from the user.
     * @return sigForUserOp - The value to put into the signature field of the userOp when calling handleOps.
     *                        (usually empty, unless account and aggregator support some kind of "multisig".
     */
    function validateUserOpSignature(PackedUserOperation calldata userOp)
        external
        view
        returns (bytes memory sigForUserOp);

    /**
     * Aggregate multiple signatures into a single value.
     * This method is called off-chain to calculate the signature to pass with handleOps()
     * bundler MAY use optimized custom code perform this aggregation.
     * @param userOps              - Array of UserOperations to collect the signatures from.
     * @return aggregatedSignature - The aggregated signature.
     */
    function aggregateSignatures(PackedUserOperation[] calldata userOps)
        external
        view
        returns (bytes memory aggregatedSignature);
}

// node_modules/@rhinestone/modulekit/src/accounts/common/interfaces/IERC7579Account.sol

/* solhint-disable no-unused-import */

// Types

// Structs
struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

interface IERC7579Account {
    event ModuleInstalled(uint256 moduleTypeId, address module);
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    /**
     * @dev Executes a transaction on behalf of the account.
     *         This function is intended to be called by ERC-4337 EntryPoint.sol
     * @dev Ensure adequate authorization control: i.e. onlyEntryPointOrSelf
     *
     * @dev MSA MUST implement this function signature.
     * If a mode is requested that is not supported by the Account, it MUST revert
     * @param mode The encoded execution mode of the transaction. See ModeLib.sol for details
     * @param executionCalldata The encoded execution call data
     */
    function execute(ModeCode mode, bytes calldata executionCalldata) external payable;

    /**
     * @dev Executes a transaction on behalf of the account.
     *         This function is intended to be called by Executor Modules
     * @dev Ensure adequate authorization control: i.e. onlyExecutorModule
     *
     * @dev MSA MUST implement this function signature.
     * If a mode is requested that is not supported by the Account, it MUST revert
     * @param mode The encoded execution mode of the transaction. See ModeLib.sol for details
     * @param executionCalldata The encoded execution call data
     */
    function executeFromExecutor(
        ModeCode mode,
        bytes calldata executionCalldata
    )
        external
        payable
        returns (bytes[] memory returnData);

    /**
     * @dev ERC-1271 isValidSignature
     *         This function is intended to be used to validate a smart account signature
     * and may forward the call to a validator module
     *
     * @param hash The hash of the data that is signed
     * @param data The data that is signed
     */
    function isValidSignature(bytes32 hash, bytes calldata data) external view returns (bytes4);

    /**
     * @dev installs a Module of a certain type on the smart account
     * @dev Implement Authorization control of your chosing
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     * @param module the module address
     * @param initData arbitrary data that may be required on the module during `onInstall`
     * initialization.
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external payable;

    /**
     * @dev uninstalls a Module of a certain type on the smart account
     * @dev Implement Authorization control of your chosing
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     * @param module the module address
     * @param deInitData arbitrary data that may be required on the module during `onUninstall`
     * de-initialization.
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external payable;

    /**
     * Function to check if the account supports a certain CallType or ExecType (see ModeLib.sol)
     * @param encodedMode the encoded mode
     */
    function supportsExecutionMode(ModeCode encodedMode) external view returns (bool);

    /**
     * Function to check if the account supports installation of a certain module type Id
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     */
    function supportsModule(uint256 moduleTypeId) external view returns (bool);

    /**
     * Function to check if the account has a certain module installed
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *      Note: keep in mind that some contracts can be multiple module types at the same time. It
     *            thus may be necessary to query multiple module types
     * @param module the module address
     * @param additionalContext additional context data that the smart account may interpret to
     *                          identifiy conditions under which the module is installed.
     *                          usually this is not necessary, but for some special hooks that
     *                          are stored in mappings, this param might be needed
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    )
        external
        view
        returns (bool);

    /**
     * @dev Returns the account id of the smart account
     * @return accountImplementationId the account id of the smart account
     * the accountId should be structured like so:
     *        "vendorname.accountname.semver"
     */
    function accountId() external view returns (string memory accountImplementationId);
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IPaymaster.sol

/**
 * The interface exposed by a paymaster contract, who agrees to pay the gas for user's operations.
 * A paymaster must hold a stake to cover the required entrypoint stake and also the gas for the transaction.
 */
interface IPaymaster {
    enum PostOpMode {
        // User op succeeded.
        opSucceeded,
        // User op reverted. Still has to pay for gas.
        opReverted,
        // Only used internally in the EntryPoint (cleanup after postOp reverts). Never calling paymaster with this
        // value
        postOpReverted
    }

    /**
     * Payment validation: check if paymaster agrees to pay.
     * Must verify sender is the entryPoint.
     * Revert to reject this request.
     * Note that bundlers will reject this method if it changes the state, unless the paymaster is trusted
     * (whitelisted).
     * The paymaster pre-pays using its deposit, and receive back a refund after the postOp method returns.
     * @param userOp          - The user operation.
     * @param userOpHash      - Hash of the user's request data.
     * @param maxCost         - The maximum cost of this transaction (based on maximum gas and gas price from userOp).
     * @return context        - Value to send to a postOp. Zero length to signify postOp is not required.
     * @return validationData - Signature and time-range of this operation, encoded the same as the return
     *                          value of validateUserOperation.
     *                          <20-byte> sigAuthorizer - 0 for valid signature, 1 to mark signature failure,
     *                                                    other values are invalid for paymaster.
     *                          <6-byte> validUntil - last timestamp this operation is valid. 0 for "indefinite"
     *                          <6-byte> validAfter - first timestamp this operation is valid
     *                          Note that the validation code cannot use block.timestamp (or block.number) directly.
     */
    function validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    )
        external
        returns (bytes memory context, uint256 validationData);

    /**
     * Post-operation handler.
     * Must verify sender is the entryPoint.
     * @param mode          - Enum with the following options:
     *                        opSucceeded - User operation succeeded.
     *                        opReverted  - User op reverted. The paymaster still has to pay for gas.
     *                        postOpReverted - never passed in a call to postOp().
     * @param context       - The context value returned by validatePaymasterUserOp
     * @param actualGasCost - Actual gas used so far (without this postOp call).
     * @param actualUserOpFeePerGas - the gas price this UserOp pays. This value is based on the UserOp's maxFeePerGas
     *                        and maxPriorityFee (and basefee)
     *                        It is not the same as tx.gasprice, which is what the bundler pays.
     */
    function postOp(
        PostOpMode mode,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 actualUserOpFeePerGas
    )
        external;
}

// node_modules/@ERC4337/account-abstraction/contracts/core/NonceManager.sol

/**
 * nonce management functionality
 */
abstract contract NonceManager is INonceManager {
    /**
     * The next valid sequence number for a given nonce key.
     */
    mapping(address => mapping(uint192 => uint256)) public nonceSequenceNumber;

    /// @inheritdoc INonceManager
    function getNonce(address sender, uint192 key) public view override returns (uint256 nonce) {
        return nonceSequenceNumber[sender][key] | (uint256(key) << 64);
    }

    // allow an account to manually increment its own nonce.
    // (mainly so that during construction nonce can be made non-zero,
    // to "absorb" the gas cost of first nonce increment to 1st transaction (construction),
    // not to 2nd transaction)
    function incrementNonce(uint192 key) public override {
        nonceSequenceNumber[msg.sender][key]++;
    }

    /**
     * validate nonce uniqueness for this account.
     * called just after validateUserOp()
     * @return true if the nonce was incremented successfully.
     *         false if the current nonce doesn't match the given one.
     */
    function _validateAndUpdateNonce(address sender, uint256 nonce) internal returns (bool) {
        uint192 key = uint192(nonce >> 64);
        uint64 seq = uint64(nonce);
        return nonceSequenceNumber[sender][key]++ == seq;
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/StakeManager.sol

/* solhint-disable avoid-low-level-calls */
/* solhint-disable not-rely-on-time */

/**
 * Manage deposits and stakes.
 * Deposit is just a balance used to pay for UserOperations (either by a paymaster or an account).
 * Stake is value locked for at least "unstakeDelay" by a paymaster.
 */
abstract contract StakeManager is IStakeManager {
    /// maps paymaster to their deposits and stakes
    mapping(address => DepositInfo) public deposits;

    /// @inheritdoc IStakeManager
    function getDepositInfo(address account) public view returns (DepositInfo memory info) {
        return deposits[account];
    }

    /**
     * Internal method to return just the stake info.
     * @param addr - The account to query.
     */
    function _getStakeInfo(address addr) internal view returns (StakeInfo memory info) {
        DepositInfo storage depositInfo = deposits[addr];
        info.stake = depositInfo.stake;
        info.unstakeDelaySec = depositInfo.unstakeDelaySec;
    }

    /// @inheritdoc IStakeManager
    function balanceOf(address account) public view returns (uint256) {
        return deposits[account].deposit;
    }

    receive() external payable {
        depositTo(msg.sender);
    }

    /**
     * Increments an account's deposit.
     * @param account - The account to increment.
     * @param amount  - The amount to increment by.
     * @return the updated deposit of this account
     */
    function _incrementDeposit(address account, uint256 amount) internal returns (uint256) {
        DepositInfo storage info = deposits[account];
        uint256 newAmount = info.deposit + amount;
        info.deposit = newAmount;
        return newAmount;
    }

    /**
     * Add to the deposit of the given account.
     * @param account - The account to add to.
     */
    function depositTo(address account) public payable virtual {
        uint256 newDeposit = _incrementDeposit(account, msg.value);
        emit Deposited(account, newDeposit);
    }

    /**
     * Add to the account's stake - amount and delay
     * any pending unstake is first cancelled.
     * @param unstakeDelaySec The new lock duration before the deposit can be withdrawn.
     */
    function addStake(uint32 unstakeDelaySec) public payable {
        DepositInfo storage info = deposits[msg.sender];
        require(unstakeDelaySec > 0, "must specify unstake delay");
        require(unstakeDelaySec >= info.unstakeDelaySec, "cannot decrease unstake time");
        uint256 stake = info.stake + msg.value;
        require(stake > 0, "no stake specified");
        require(stake <= type(uint112).max, "stake overflow");
        deposits[msg.sender] = DepositInfo(info.deposit, true, uint112(stake), unstakeDelaySec, 0);
        emit StakeLocked(msg.sender, stake, unstakeDelaySec);
    }

    /**
     * Attempt to unlock the stake.
     * The value can be withdrawn (using withdrawStake) after the unstake delay.
     */
    function unlockStake() external {
        DepositInfo storage info = deposits[msg.sender];
        require(info.unstakeDelaySec != 0, "not staked");
        require(info.staked, "already unstaking");
        uint48 withdrawTime = uint48(block.timestamp) + info.unstakeDelaySec;
        info.withdrawTime = withdrawTime;
        info.staked = false;
        emit StakeUnlocked(msg.sender, withdrawTime);
    }

    /**
     * Withdraw from the (unlocked) stake.
     * Must first call unlockStake and wait for the unstakeDelay to pass.
     * @param withdrawAddress - The address to send withdrawn value.
     */
    function withdrawStake(address payable withdrawAddress) external {
        DepositInfo storage info = deposits[msg.sender];
        uint256 stake = info.stake;
        require(stake > 0, "No stake to withdraw");
        require(info.withdrawTime > 0, "must call unlockStake() first");
        require(info.withdrawTime <= block.timestamp, "Stake withdrawal is not due");
        info.unstakeDelaySec = 0;
        info.withdrawTime = 0;
        info.stake = 0;
        emit StakeWithdrawn(msg.sender, withdrawAddress, stake);
        (bool success,) = withdrawAddress.call{ value: stake }("");
        require(success, "failed to withdraw stake");
    }

    /**
     * Withdraw from the deposit.
     * @param withdrawAddress - The address to send withdrawn value.
     * @param withdrawAmount  - The amount to withdraw.
     */
    function withdrawTo(address payable withdrawAddress, uint256 withdrawAmount) external {
        DepositInfo storage info = deposits[msg.sender];
        require(withdrawAmount <= info.deposit, "Withdraw amount too large");
        info.deposit = info.deposit - withdrawAmount;
        emit Withdrawn(msg.sender, withdrawAddress, withdrawAmount);
        (bool success,) = withdrawAddress.call{ value: withdrawAmount }("");
        require(success, "failed to withdraw");
    }
}

// node_modules/@rhinestone/modulekit/src/accounts/erc7579/lib/ExecutionLib.sol

// Types

/**
 * Helper Library for decoding Execution calldata
 * malloc for memory allocation is bad for gas. use this assembly instead
 */
library ExecutionLib {
    error ERC7579DecodingError();

    /**
     * @notice Decode a batch of `Execution` executionBatch from a `bytes` calldata.
     * @dev code is copied from solady's LibERC7579.sol
     * https://github.com/Vectorized/solady/blob/740812cedc9a1fc11e17cb3d4569744367dedf19/src/accounts/LibERC7579.sol#L146
     *      Credits to Vectorized and the Solady Team
     */
    function decodeBatch(bytes calldata executionCalldata)
        internal
        pure
        returns (Execution[] calldata executionBatch)
    {
        /// @solidity memory-safe-assembly
        assembly {
            let u := calldataload(executionCalldata.offset)
            let s := add(executionCalldata.offset, u)
            let e := sub(add(executionCalldata.offset, executionCalldata.length), 0x20)
            executionBatch.offset := add(s, 0x20)
            executionBatch.length := calldataload(s)
            if or(shr(64, u), gt(add(s, shl(5, executionBatch.length)), e)) {
                mstore(0x00, 0xba597e7e) // `DecodingError()`.
                revert(0x1c, 0x04)
            }
            if executionBatch.length {
                // Perform bounds checks on the decoded `executionBatch`.
                // Loop runs out-of-gas if `executionBatch.length` is big enough to cause overflows.
                for { let i := executionBatch.length } 1 { } {
                    i := sub(i, 1)
                    let p := calldataload(add(executionBatch.offset, shl(5, i)))
                    let c := add(executionBatch.offset, p)
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

// node_modules/@ERC4337/account-abstraction/contracts/core/UserOperationLib.sol

/* solhint-disable no-inline-assembly */

/**
 * Utility functions helpful when working with UserOperation structs.
 */
library UserOperationLib {
    uint256 public constant PAYMASTER_VALIDATION_GAS_OFFSET = 20;
    uint256 public constant PAYMASTER_POSTOP_GAS_OFFSET = 36;
    uint256 public constant PAYMASTER_DATA_OFFSET = 52;
    /**
     * Get sender from user operation data.
     * @param userOp - The user operation data.
     */

    function getSender(PackedUserOperation calldata userOp) internal pure returns (address) {
        address data;
        //read sender from userOp, which is first userOp member (saves 800 gas...)
        assembly {
            data := calldataload(userOp)
        }
        return address(uint160(data));
    }

    /**
     * Relayer/block builder might submit the TX with higher priorityFee,
     * but the user should not pay above what he signed for.
     * @param userOp - The user operation data.
     */
    function gasPrice(PackedUserOperation calldata userOp) internal view returns (uint256) {
        unchecked {
            (uint256 maxPriorityFeePerGas, uint256 maxFeePerGas) = unpackUints(userOp.gasFees);
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    /**
     * Pack the user operation data into bytes for hashing.
     * @param userOp - The user operation data.
     */
    function encode(PackedUserOperation calldata userOp) internal pure returns (bytes memory ret) {
        address sender = getSender(userOp);
        uint256 nonce = userOp.nonce;
        bytes32 hashInitCode = calldataKeccak(userOp.initCode);
        bytes32 hashCallData = calldataKeccak(userOp.callData);
        bytes32 accountGasLimits = userOp.accountGasLimits;
        uint256 preVerificationGas = userOp.preVerificationGas;
        bytes32 gasFees = userOp.gasFees;
        bytes32 hashPaymasterAndData = calldataKeccak(userOp.paymasterAndData);

        return abi.encode(
            sender,
            nonce,
            hashInitCode,
            hashCallData,
            accountGasLimits,
            preVerificationGas,
            gasFees,
            hashPaymasterAndData
        );
    }

    function unpackUints(bytes32 packed) internal pure returns (uint256 high128, uint256 low128) {
        return (uint128(bytes16(packed)), uint128(uint256(packed)));
    }

    //unpack just the high 128-bits from a packed value
    function unpackHigh128(bytes32 packed) internal pure returns (uint256) {
        return uint256(packed) >> 128;
    }

    // unpack just the low 128-bits from a packed value
    function unpackLow128(bytes32 packed) internal pure returns (uint256) {
        return uint128(uint256(packed));
    }

    function unpackMaxPriorityFeePerGas(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return unpackHigh128(userOp.gasFees);
    }

    function unpackMaxFeePerGas(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return unpackLow128(userOp.gasFees);
    }

    function unpackVerificationGasLimit(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return unpackHigh128(userOp.accountGasLimits);
    }

    function unpackCallGasLimit(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return unpackLow128(userOp.accountGasLimits);
    }

    function unpackPaymasterVerificationGasLimit(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_POSTOP_GAS_OFFSET]));
    }

    function unpackPostOpGasLimit(PackedUserOperation calldata userOp) internal pure returns (uint256) {
        return uint128(bytes16(userOp.paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET]));
    }

    function unpackPaymasterStaticFields(bytes calldata paymasterAndData)
        internal
        pure
        returns (address paymaster, uint256 validationGasLimit, uint256 postOpGasLimit)
    {
        return (
            address(bytes20(paymasterAndData[:PAYMASTER_VALIDATION_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_VALIDATION_GAS_OFFSET:PAYMASTER_POSTOP_GAS_OFFSET])),
            uint128(bytes16(paymasterAndData[PAYMASTER_POSTOP_GAS_OFFSET:PAYMASTER_DATA_OFFSET]))
        );
    }

    /**
     * Hash the user operation data.
     * @param userOp - The user operation data.
     */
    function hash(PackedUserOperation calldata userOp) internal pure returns (bytes32) {
        return keccak256(encode(userOp));
    }
}

// node_modules/@rhinestone/modulekit/src/accounts/common/interfaces/IERC7579Module.sol

// Types

// Constants
uint256 constant VALIDATION_SUCCESS = 0;
uint256 constant VALIDATION_FAILED = 1;
uint256 constant MODULE_TYPE_VALIDATOR_1 = 1;
uint256 constant MODULE_TYPE_EXECUTOR_1 = 2;
uint256 constant MODULE_TYPE_FALLBACK_1 = 3;
uint256 constant MODULE_TYPE_HOOK_1 = 4;
uint256 constant MODULE_TYPE_PREVALIDATION_HOOK_ERC1271 = 8;
uint256 constant MODULE_TYPE_PREVALIDATION_HOOK_ERC4337 = 9;

interface IModule {
    error ModuleAlreadyInitialized(address smartAccount);
    error NotInitialized(address smartAccount);

    /**
     * @dev This function is called by the smart account during installation of the module
     * @param data arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external;

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external;

    /**
     * @dev Returns boolean value if module is a certain type
     * @param moduleTypeId the module type ID according the ERC-7579 spec
     *
     * MUST return true if the module is of the given type and false otherwise
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool);

    /**
     * @dev Returns if the module was already initialized for a provided smartaccount
     */
    function isInitialized(address smartAccount) external view returns (bool);
}

interface IValidator is IModule {
    error InvalidTargetAddress(address target);

    /**
     * @dev Validates a transaction on behalf of the account.
     *         This function is intended to be called by the MSA during the ERC-4337 validaton phase
     *         Note: solely relying on bytes32 hash and signature is not sufficient for some
     * validation implementations (i.e. SessionKeys often need access to userOp.calldata)
     * @param userOp The user operation to be validated. The userOp MUST NOT contain any metadata.
     * The MSA MUST clean up the userOp before sending it to the validator.
     * @param userOpHash The hash of the user operation to be validated
     * @return return value according to ERC-4337
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256);

    /**
     * Validator can be used for ERC-1271 validation
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes4);
}

interface IExecutor is IModule { }

interface IHook is IModule {
    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        external
        returns (bytes memory hookData);

    function postCheck(bytes calldata hookData) external;
}

interface IFallback is IModule { }

interface IPolicy_0 is IModule {
    function checkUserOpPolicy(bytes32 id, PackedUserOperation calldata userOp) external payable returns (uint256);
    function checkSignaturePolicy(
        bytes32 id,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (uint256);
}

interface ISigner is IModule {
    function checkUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256);
    function checkSignature(
        bytes32 id,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (bytes4);
}

interface IPreValidationHookERC1271 is IModule {
    function preValidationHookERC1271(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        returns (bytes32 hookHash, bytes memory hookSignature);
}

interface IPreValidationHookERC4337 is IModule {
    function preValidationHookERC4337(
        PackedUserOperation calldata userOp,
        uint256 missingAccountFunds,
        bytes32 userOpHash
    )
        external
        returns (bytes32 hookHash, bytes memory hookSignature);
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IEntryPoint.sol
/**
 * Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 * Only one instance required on each chain.
 *
 */

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

interface IEntryPoint is IStakeManager, INonceManager {
    /**
     *
     * An event emitted after each successful request.
     * @param userOpHash    - Unique identifier for the request (hash its entire content, except signature).
     * @param sender        - The account that generates this request.
     * @param paymaster     - If non-null, the paymaster that pays for this request.
     * @param nonce         - The nonce value from the request.
     * @param success       - True if the sender transaction succeeded, false if reverted.
     * @param actualGasCost - Actual amount paid (by account or paymaster) for this UserOperation.
     * @param actualGasUsed - Total gas used by this UserOperation (including preVerification, creation,
     *                        validation and execution).
     */
    event UserOperationEvent(
        bytes32 indexed userOpHash,
        address indexed sender,
        address indexed paymaster,
        uint256 nonce,
        bool success,
        uint256 actualGasCost,
        uint256 actualGasUsed
    );

    /**
     * Account "sender" was deployed.
     * @param userOpHash - The userOp that deployed this account. UserOperationEvent will follow.
     * @param sender     - The account that is deployed
     * @param factory    - The factory used to deploy this account (in the initCode)
     * @param paymaster  - The paymaster used by this UserOp
     */
    event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster);

    /**
     * An event emitted if the UserOperation "callData" reverted with non-zero length.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     * @param revertReason - The return bytes from the (reverted) call to "callData".
     */
    event UserOperationRevertReason(
        bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason
    );

    /**
     * An event emitted if the UserOperation Paymaster's "postOp" call reverted with non-zero length.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     * @param revertReason - The return bytes from the (reverted) call to "callData".
     */
    event PostOpRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason);

    /**
     * UserOp consumed more than prefund. The UserOperation is reverted, and no refund is made.
     * @param userOpHash   - The request unique identifier.
     * @param sender       - The sender of this request.
     * @param nonce        - The nonce used in the request.
     */
    event UserOperationPrefundTooLow(bytes32 indexed userOpHash, address indexed sender, uint256 nonce);

    /**
     * An event emitted by handleOps(), before starting the execution loop.
     * Any event emitted before this event, is part of the validation.
     */
    event BeforeExecution();

    /**
     * Signature aggregator used by the following UserOperationEvents within this bundle.
     * @param aggregator - The aggregator used for the following UserOperationEvents.
     */
    event SignatureAggregatorChanged(address indexed aggregator);

    /**
     * A custom revert error of handleOps, to identify the offending op.
     * Should be caught in off-chain handleOps simulation and not happen on-chain.
     * Useful for mitigating DoS attempts against batchers or for troubleshooting of factory/account/paymaster reverts.
     * NOTE: If simulateValidation passes successfully, there should be no reason for handleOps to fail on it.
     * @param opIndex - Index into the array of ops to the failed one (in simulateValidation, this is always zero).
     * @param reason  - Revert reason. The string starts with a unique code "AAmn",
     *                  where "m" is "1" for factory, "2" for account and "3" for paymaster issues,
     *                  so a failure can be attributed to the correct entity.
     */
    error FailedOp(uint256 opIndex, string reason);

    /**
     * A custom revert error of handleOps, to report a revert by account or paymaster.
     * @param opIndex - Index into the array of ops to the failed one (in simulateValidation, this is always zero).
     * @param reason  - Revert reason. see FailedOp(uint256,string), above
     * @param inner   - data from inner cought revert reason
     * @dev note that inner is truncated to 2048 bytes
     */
    error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner);

    error PostOpReverted(bytes returnData);

    /**
     * Error case when a signature aggregator fails to verify the aggregated signature it had created.
     * @param aggregator The aggregator that failed to verify the signature
     */
    error SignatureValidationFailed(address aggregator);

    // Return value of getSenderAddress.
    error SenderAddressResult(address sender);

    // UserOps handled, per aggregator.
    struct UserOpsPerAggregator {
        PackedUserOperation[] userOps;
        // Aggregator address
        IAggregator aggregator;
        // Aggregated signature
        bytes signature;
    }

    /**
     * Execute a batch of UserOperations.
     * No signature aggregator is used.
     * If any account requires an aggregator (that is, it returned an aggregator when
     * performing simulateValidation), then handleAggregatedOps() must be used instead.
     * @param ops         - The operations to execute.
     * @param beneficiary - The address to receive the fees.
     */
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) external;

    /**
     * Execute a batch of UserOperation with Aggregators
     * @param opsPerAggregator - The operations to execute, grouped by aggregator (or address(0) for no-aggregator
     * accounts).
     * @param beneficiary      - The address to receive the fees.
     */
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    )
        external;

    /**
     * Generate a request Id - unique identifier for this request.
     * The request ID is a hash over the content of the userOp (except the signature), the entrypoint and the chainid.
     * @param userOp - The user operation to generate the request ID for.
     * @return hash the hash of this UserOperation
     */
    function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);

    /**
     * Gas and return values during simulation.
     * @param preOpGas         - The gas used for validation (including preValidationGas)
     * @param prefund          - The required prefund for this operation
     * @param accountValidationData   - returned validationData from account.
     * @param paymasterValidationData - return validationData from paymaster.
     * @param paymasterContext - Returned by validatePaymasterUserOp (to be passed into postOp)
     */
    struct ReturnInfo {
        uint256 preOpGas;
        uint256 prefund;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
        bytes paymasterContext;
    }

    /**
     * Returned aggregated signature info:
     * The aggregator returned by the account, and its current stake.
     */
    struct AggregatorStakeInfo {
        address aggregator;
        StakeInfo stakeInfo;
    }

    /**
     * Get counterfactual sender address.
     * Calculate the sender contract address that will be generated by the initCode and salt in the UserOperation.
     * This method always revert, and returns the address in SenderAddressResult error
     * @param initCode - The constructor code to be passed into the UserOperation.
     */
    function getSenderAddress(bytes memory initCode) external;

    error DelegateAndRevert(bool success, bytes ret);

    /**
     * Helper method for dry-run testing.
     * @dev calling this method, the EntryPoint will make a delegatecall to the given data, and report (via revert) the
     * result.
     *  The method always revert, so is only useful off-chain for dry run calls, in cases where state-override to
     * replace
     *  actual EntryPoint code is less convenient.
     * @param target a target contract to make a delegatecall from entrypoint
     * @param data data to pass to target in a delegatecall
     */
    function delegateAndRevert(address target, bytes calldata data) external;
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579ModuleBase.sol

abstract contract ERC7579ModuleBase is IModule {
    uint256 internal constant TYPE_VALIDATOR = MODULE_TYPE_VALIDATOR_0;
    uint256 internal constant TYPE_EXECUTOR = MODULE_TYPE_EXECUTOR_0;
    uint256 internal constant TYPE_FALLBACK = MODULE_TYPE_FALLBACK_0;
    uint256 internal constant TYPE_HOOK = MODULE_TYPE_HOOK_0;
    uint256 internal constant TYPE_POLICY = MODULE_TYPE_POLICY;
    uint256 internal constant TYPE_SIGNER = MODULE_TYPE_SIGNER;
    uint256 internal constant TYPE_STATELESS_VALIDATOR = MODULE_TYPE_STATELESS_VALIDATOR;
}

// node_modules/@ERC4337/account-abstraction/contracts/interfaces/IEntryPointSimulations.sol

interface IEntryPointSimulations is IEntryPoint {
    // Return value of simulateHandleOp.
    struct ExecutionResult {
        uint256 preOpGas;
        uint256 paid;
        uint256 accountValidationData;
        uint256 paymasterValidationData;
        bool targetSuccess;
        bytes targetResult;
    }

    /**
     * Successful result from simulateValidation.
     * If the account returns a signature aggregator the "aggregatorInfo" struct is filled in as well.
     * @param returnInfo     Gas and time-range returned values
     * @param senderInfo     Stake information about the sender
     * @param factoryInfo    Stake information about the factory (if any)
     * @param paymasterInfo  Stake information about the paymaster (if any)
     * @param aggregatorInfo Signature aggregation info (if the account requires signature aggregator)
     *                       Bundler MUST use it to verify the signature, or reject the UserOperation.
     */
    struct ValidationResult {
        ReturnInfo returnInfo;
        StakeInfo senderInfo;
        StakeInfo factoryInfo;
        StakeInfo paymasterInfo;
        AggregatorStakeInfo aggregatorInfo;
    }

    /**
     * Simulate a call to account.validateUserOp and paymaster.validatePaymasterUserOp.
     * @dev The node must also verify it doesn't use banned opcodes, and that it doesn't reference storage
     *      outside the account's data.
     * @param userOp - The user operation to validate.
     * @return the validation result structure
     */
    function simulateValidation(PackedUserOperation calldata userOp) external returns (ValidationResult memory);

    /**
     * Simulate full execution of a UserOperation (including both validation and target execution)
     * It performs full validation of the UserOperation, but ignores signature error.
     * An optional target address is called after the userop succeeds,
     * and its value is returned (before the entire call is reverted).
     * Note that in order to collect the the success/failure of the target call, it must be executed
     * with trace enabled to track the emitted events.
     * @param op The UserOperation to simulate.
     * @param target         - If nonzero, a target address to call after userop simulation. If called,
     *                         the targetSuccess and targetResult are set to the return from that call.
     * @param targetCallData - CallData to pass to target address.
     * @return the execution result structure
     */
    function simulateHandleOp(
        PackedUserOperation calldata op,
        address target,
        bytes calldata targetCallData
    )
        external
        returns (ExecutionResult memory);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579FallbackBase.sol

abstract contract ERC7579FallbackBase is IFallback, ERC7579ModuleBase {
    /**
     * @notice Allows fetching the original caller address.
     * @dev This is only reliable in combination with a FallbackManager that supports this (e.g. Safe
     * contract >=1.3.0).
     *      When using this functionality make sure that the linked _manager (aka msg.sender)
     * supports this.
     *      This function does not rely on a trusted forwarder. Use the returned value only to
     *      check information against the calling manager.
     * @return sender Original caller address.
     */
    function _msgSender() internal pure returns (address sender) {
        // The assembly code is more direct than the Solidity version using `abi.decode`.
        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            sender := shr(96, calldataload(sub(calldatasize(), 20)))
        }
        /* solhint-enable no-inline-assembly */
    }
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579HookBase.sol

abstract contract ERC7579HookBase is IHook, ERC7579ModuleBase, TrustedForwarder {
    /**
     * Precheck hook
     *
     * @param msgSender sender of the transaction
     * @param msgValue value of the transaction
     * @param msgData data of the transaction
     *
     * @return hookData data for the postcheck hook
     */
    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        external
        virtual
        returns (bytes memory hookData)
    {
        // route to internal function
        return _preCheck(_getAccount(), msgSender, msgValue, msgData);
    }

    /**
     * Postcheck hook
     *
     * @param hookData data from the precheck hook
     */
    function postCheck(bytes calldata hookData) external virtual {
        // route to internal function
        _postCheck(_getAccount(), hookData);
    }

    /**
     * Precheck hook
     *
     * @param account account of the transaction
     * @param msgSender sender of the transaction
     * @param msgValue value of the transaction
     * @param msgData data of the transaction
     *
     * @return hookData data for the postcheck hook
     */
    function _preCheck(
        address account,
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        internal
        virtual
        returns (bytes memory hookData);

    /**
     * Postcheck hook
     *
     * @param account account of the transaction
     * @param hookData data from the precheck hook
     */
    function _postCheck(address account, bytes calldata hookData) internal virtual;
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579StatelessValidatorBase.sol

abstract contract ERC7579StatelessValidatorBase is ERC7579ModuleBase, IStatelessValidator {
    function validateSignatureWithData(
        bytes32,
        bytes calldata,
        bytes calldata
    )
        external
        view
        virtual
        returns (bool validSig);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579ExecutorBase.sol

abstract contract ERC7579ExecutorBase is IExecutor, ERC7579ModuleBase {
    function _execute(
        address account,
        address to,
        uint256 value,
        bytes memory data
    )
        internal
        returns (bytes memory result)
    {
        ModeCode modeCode = ModeLib.encode({
            callType: CALLTYPE_SINGLE,
            execType: EXECTYPE_DEFAULT,
            mode: MODE_DEFAULT,
            payload: ModePayload.wrap(bytes22(0))
        });

        return IERC7579Account(account).executeFromExecutor(modeCode, ExecutionLib.encodeSingle(to, value, data))[0];
    }

    function _execute(address to, uint256 value, bytes memory data) internal returns (bytes memory result) {
        return _execute(msg.sender, to, value, data);
    }

    function _execute(address account, Execution[] memory execs) internal returns (bytes[] memory results) {
        ModeCode modeCode = ModeLib.encode({
            callType: CALLTYPE_BATCH,
            execType: EXECTYPE_DEFAULT,
            mode: MODE_DEFAULT,
            payload: ModePayload.wrap(bytes22(0))
        });
        results = IERC7579Account(account).executeFromExecutor(modeCode, ExecutionLib.encodeBatch(execs));
    }

    function _execute(Execution[] memory execs) internal returns (bytes[] memory results) {
        return _execute(msg.sender, execs);
    }

    // Note: Not every account will support delegatecalls
    function _executeDelegateCall(
        address account,
        address delegateTarget,
        bytes memory callData
    )
        internal
        returns (bytes[] memory results)
    {
        ModeCode modeCode = ModeLib.encode({
            callType: CALLTYPE_DELEGATECALL,
            execType: EXECTYPE_DEFAULT,
            mode: MODE_DEFAULT,
            payload: ModePayload.wrap(bytes22(0))
        });
        results = IERC7579Account(account).executeFromExecutor(modeCode, abi.encodePacked(delegateTarget, callData));
    }

    // Note: Not every account will support delegatecalls
    function _executeDelegateCall(
        address delegateTarget,
        bytes memory callData
    )
        internal
        returns (bytes[] memory results)
    {
        return _executeDelegateCall(msg.sender, delegateTarget, callData);
    }
}

// node_modules/@rhinestone/modulekit/src/module-bases/SchedulingBase.sol

abstract contract SchedulingBase is ERC7579ExecutorBase {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    error InvalidExecution();

    event ExecutionAdded(address indexed smartAccount, uint256 indexed jobId);
    event ExecutionTriggered(address indexed smartAccount, uint256 indexed jobId);
    event ExecutionStatusUpdated(address indexed smartAccount, uint256 indexed jobId);
    event ExecutionsCancelled(address indexed smartAccount);

    mapping(address smartAccount => mapping(uint256 jobId => ExecutionConfig)) public executionLog;

    mapping(address smartAccount => uint256 jobCount) public accountJobCount;

    struct ExecutionConfig {
        uint48 executeInterval;
        uint16 numberOfExecutions;
        uint16 numberOfExecutionsCompleted;
        uint48 startDate;
        bool isEnabled;
        uint48 lastExecutionTime;
        bytes executionData;
    }

    struct ExecutorAccess {
        uint256 jobId;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    function _onInstall(bytes calldata packedSchedulingData) internal {
        address account = msg.sender;
        if (isInitialized(account)) {
            revert ModuleAlreadyInitialized(account);
        }

        _createExecution({ orderData: packedSchedulingData });
    }

    function _onUninstall() internal {
        address account = msg.sender;

        uint256 count = accountJobCount[account];
        for (uint256 i = 1; i <= count; i++) {
            delete executionLog[account][i];
        }
        accountJobCount[account] = 0;

        emit ExecutionsCancelled(account);
    }

    function isInitialized(address smartAccount) public view returns (bool) {
        return accountJobCount[smartAccount] != 0;
    }

    function addOrder(bytes calldata orderData) external {
        address account = msg.sender;
        if (!isInitialized(account)) revert NotInitialized(account);

        _createExecution({ orderData: orderData });
    }

    function toggleOrder(uint256 jobId) external {
        address account = msg.sender;

        ExecutionConfig storage executionConfig = executionLog[account][jobId];

        if (executionConfig.numberOfExecutions == 0) {
            revert InvalidExecution();
        }

        executionConfig.isEnabled = !executionConfig.isEnabled;

        emit ExecutionStatusUpdated(account, jobId);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _createExecution(bytes calldata orderData) internal {
        address account = msg.sender;

        uint256 jobId = accountJobCount[account] + 1;
        accountJobCount[account]++;

        // prevent user from supplying an invalid number of execution (0)
        uint16 nrOfExecutions = uint16(bytes2(orderData[6:8]));
        if (nrOfExecutions == 0) revert InvalidExecution();

        executionLog[account][jobId] = ExecutionConfig({
            numberOfExecutionsCompleted: 0,
            isEnabled: true,
            lastExecutionTime: 0,
            executeInterval: uint48(bytes6(orderData[0:6])),
            numberOfExecutions: nrOfExecutions,
            startDate: uint48(bytes6(orderData[8:14])),
            executionData: orderData[14:]
        });

        emit ExecutionAdded(account, jobId);
    }

    function _isExecutionValid(uint256 jobId) internal view {
        ExecutionConfig storage executionConfig = executionLog[msg.sender][jobId];

        if (!executionConfig.isEnabled) {
            revert InvalidExecution();
        }

        if (executionConfig.lastExecutionTime + executionConfig.executeInterval > block.timestamp) {
            revert InvalidExecution();
        }

        if (executionConfig.numberOfExecutionsCompleted >= executionConfig.numberOfExecutions) {
            revert InvalidExecution();
        }

        if (executionConfig.startDate > block.timestamp) {
            revert InvalidExecution();
        }
    }

    modifier canExecute(uint256 jobId) {
        _isExecutionValid(jobId);
        _;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_EXECUTOR;
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/EntryPoint.sol

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

/*
 * Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 * Only one instance required on each chain.
 */

/// @custom:security-contact https://bounty.ethereum.org
contract EntryPoint is IEntryPoint, StakeManager, NonceManager, ReentrancyGuard, ERC165, GasDebug {
    using UserOperationLib for PackedUserOperation;

    SenderCreator private immutable _senderCreator = new SenderCreator();

    function senderCreator() internal view virtual returns (SenderCreator) {
        return _senderCreator;
    }

    //compensate for innerHandleOps' emit message and deposit refund.
    // allow some slack for future gas price changes.
    uint256 private constant INNER_GAS_OVERHEAD = 10_000;

    // Marker for inner call revert on out of gas
    bytes32 private constant INNER_OUT_OF_GAS = hex"deaddead";
    bytes32 private constant INNER_REVERT_LOW_PREFUND = hex"deadaa51";

    uint256 private constant REVERT_REASON_MAX_LEN = 2048;
    uint256 private constant PENALTY_PERCENT = 10;

    /// @inheritdoc IERC165_0
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        // note: solidity "type(IEntryPoint).interfaceId" is without inherited methods but we want to check everything
        return interfaceId
            == (type(IEntryPoint).interfaceId ^ type(IStakeManager).interfaceId ^ type(INonceManager).interfaceId)
            || interfaceId == type(IEntryPoint).interfaceId || interfaceId == type(IStakeManager).interfaceId
            || interfaceId == type(INonceManager).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * Compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary - The address to receive the fees.
     * @param amount      - Amount to transfer.
     */
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        (bool success,) = beneficiary.call{ value: amount }("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * Execute a user operation.
     * @param opIndex    - Index into the opInfo array.
     * @param userOp     - The userOp to execute.
     * @param opInfo     - The opInfo filled by validatePrepayment for this userOp.
     * @return collected - The total amount this userOp paid.
     */
    function _executeUserOp(
        uint256 opIndex,
        PackedUserOperation calldata userOp,
        UserOpInfo memory opInfo
    )
        internal
        returns (uint256 collected)
    {
        uint256 preGas = gasleft();
        bytes memory context = getMemoryBytesFromOffset(opInfo.contextOffset);
        bool success;
        {
            uint256 saveFreePtr;
            assembly ("memory-safe") {
                saveFreePtr := mload(0x40)
            }
            bytes calldata callData = userOp.callData;
            bytes memory innerCall;
            bytes4 methodSig;
            assembly {
                let len := callData.length
                if gt(len, 3) { methodSig := calldataload(callData.offset) }
            }
            if (methodSig == IAccountExecute.executeUserOp.selector) {
                bytes memory executeUserOp = abi.encodeCall(IAccountExecute.executeUserOp, (userOp, opInfo.userOpHash));
                innerCall = abi.encodeCall(this.innerHandleOp, (executeUserOp, opInfo, context));
            } else {
                innerCall = abi.encodeCall(this.innerHandleOp, (callData, opInfo, context));
            }
            assembly ("memory-safe") {
                success := call(gas(), address(), 0, add(innerCall, 0x20), mload(innerCall), 0, 32)
                collected := mload(0)
                mstore(0x40, saveFreePtr)
            }
        }
        if (!success) {
            bytes32 innerRevertCode;
            assembly ("memory-safe") {
                let len := returndatasize()
                if eq(32, len) {
                    returndatacopy(0, 0, 32)
                    innerRevertCode := mload(0)
                }
            }
            if (innerRevertCode == INNER_OUT_OF_GAS) {
                // handleOps was called with gas limit too low. abort entire bundle.
                //can only be caused by bundler (leaving not enough gas for inner call)
                revert FailedOp(opIndex, "AA95 out of gas");
            } else if (innerRevertCode == INNER_REVERT_LOW_PREFUND) {
                // innerCall reverted on prefund too low. treat entire prefund as "gas cost"
                uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
                uint256 actualGasCost = opInfo.prefund;
                emitPrefundTooLow(opInfo);
                emitUserOperationEvent(opInfo, false, actualGasCost, actualGas);
                collected = actualGasCost;
            } else {
                emit PostOpRevertReason(
                    opInfo.userOpHash,
                    opInfo.mUserOp.sender,
                    opInfo.mUserOp.nonce,
                    Exec.getReturnData(REVERT_REASON_MAX_LEN)
                );

                uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
                collected = _postExecution(IPaymaster.PostOpMode.postOpReverted, opInfo, context, actualGas);
            }
        }
    }

    function emitUserOperationEvent(
        UserOpInfo memory opInfo,
        bool success,
        uint256 actualGasCost,
        uint256 actualGas
    )
        internal
        virtual
    {
        emit UserOperationEvent(
            opInfo.userOpHash,
            opInfo.mUserOp.sender,
            opInfo.mUserOp.paymaster,
            opInfo.mUserOp.nonce,
            success,
            actualGasCost,
            actualGas
        );
    }

    function emitPrefundTooLow(UserOpInfo memory opInfo) internal virtual {
        emit UserOperationPrefundTooLow(opInfo.userOpHash, opInfo.mUserOp.sender, opInfo.mUserOp.nonce);
    }

    /// @inheritdoc IEntryPoint
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) public nonReentrant {
        uint256 opslen = ops.length;
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        unchecked {
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[i];
                (uint256 validationData, uint256 pmValidationData) = _validatePrepayment(i, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(i, validationData, pmValidationData, address(0));
            }

            uint256 collected = 0;
            emit BeforeExecution();

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(i, ops[i], opInfos[i]);
            }

            _compensate(beneficiary, collected);
        }
    }

    /// @inheritdoc IEntryPoint
    function handleAggregatedOps(
        UserOpsPerAggregator[] calldata opsPerAggregator,
        address payable beneficiary
    )
        public
        nonReentrant
    {
        uint256 opasLen = opsPerAggregator.length;
        uint256 totalOps = 0;
        for (uint256 i = 0; i < opasLen; i++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[i];
            PackedUserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            //address(1) is special marker of "signature error"
            require(address(aggregator) != address(1), "AA96 invalid aggregator");

            if (address(aggregator) != address(0)) {
                // solhint-disable-next-line no-empty-blocks
                try aggregator.validateSignatures(ops, opa.signature) { }
                catch {
                    revert SignatureValidationFailed(address(aggregator));
                }
            }

            totalOps += ops.length;
        }

        UserOpInfo[] memory opInfos = new UserOpInfo[](totalOps);

        uint256 opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            PackedUserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            uint256 opslen = ops.length;
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[opIndex];
                (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(opIndex, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(
                    i, validationData, paymasterValidationData, address(aggregator)
                );
                opIndex++;
            }
        }

        emit BeforeExecution();

        uint256 collected = 0;
        opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            emit SignatureAggregatorChanged(address(opa.aggregator));
            PackedUserOperation[] calldata ops = opa.userOps;
            uint256 opslen = ops.length;

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(opIndex, ops[i], opInfos[opIndex]);
                opIndex++;
            }
        }
        emit SignatureAggregatorChanged(address(0));

        _compensate(beneficiary, collected);
    }

    /**
     * A memory copy of UserOp static fields only.
     * Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
     */
    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 verificationGasLimit;
        uint256 callGasLimit;
        uint256 paymasterVerificationGasLimit;
        uint256 paymasterPostOpGasLimit;
        uint256 preVerificationGas;
        address paymaster;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 prefund;
        uint256 contextOffset;
        uint256 preOpGas;
    }

    /**
     * Inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps.
     * @param callData - The callData to execute.
     * @param opInfo   - The UserOpInfo struct.
     * @param context  - The context bytes.
     * @return actualGasCost - the actual cost in eth this UserOperation paid for gas
     */
    function innerHandleOp(
        bytes memory callData,
        UserOpInfo memory opInfo,
        bytes calldata context
    )
        external
        returns (uint256 actualGasCost)
    {
        uint256 preGas = gasleft();
        require(msg.sender == address(this), "AA92 internal call only");
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        uint256 callGasLimit = mUserOp.callGasLimit;
        unchecked {
            // handleOps was called with gas limit too low. abort entire bundle.
            if (gasleft() * 63 / 64 < callGasLimit + mUserOp.paymasterPostOpGasLimit + INNER_GAS_OVERHEAD) {
                assembly ("memory-safe") {
                    mstore(0, INNER_OUT_OF_GAS)
                    revert(0, 32)
                }
            }
        }

        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;
        if (callData.length > 0) {
            uint256 _execGas = gasleft();
            bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);
            setGasConsumed(mUserOp.sender, 2, _execGas - gasleft());
            if (!success) {
                bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                if (result.length > 0) {
                    emit UserOperationRevertReason(opInfo.userOpHash, mUserOp.sender, mUserOp.nonce, result);
                }
                mode = IPaymaster.PostOpMode.opReverted;
            }
        }

        unchecked {
            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            return _postExecution(mode, opInfo, context, actualGas);
        }
    }

    /// @inheritdoc IEntryPoint
    function getUserOpHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /**
     * Copy general fields from userOp into the memory opInfo structure.
     * @param userOp  - The user operation.
     * @param mUserOp - The memory user operation.
     */
    function _copyUserOpToMemory(PackedUserOperation calldata userOp, MemoryUserOp memory mUserOp) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;
        (mUserOp.verificationGasLimit, mUserOp.callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        (mUserOp.maxPriorityFeePerGas, mUserOp.maxFeePerGas) = UserOperationLib.unpackUints(userOp.gasFees);
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length > 0) {
            require(paymasterAndData.length >= UserOperationLib.PAYMASTER_DATA_OFFSET, "AA93 invalid paymasterAndData");
            (mUserOp.paymaster, mUserOp.paymasterVerificationGasLimit, mUserOp.paymasterPostOpGasLimit) =
                UserOperationLib.unpackPaymasterStaticFields(paymasterAndData);
        } else {
            mUserOp.paymaster = address(0);
            mUserOp.paymasterVerificationGasLimit = 0;
            mUserOp.paymasterPostOpGasLimit = 0;
        }
    }

    /**
     * Get the required prefunded gas fee amount for an operation.
     * @param mUserOp - The user operation in memory.
     */
    function _getRequiredPrefund(MemoryUserOp memory mUserOp) internal pure returns (uint256 requiredPrefund) {
        unchecked {
            uint256 requiredGas = mUserOp.verificationGasLimit + mUserOp.callGasLimit
                + mUserOp.paymasterVerificationGasLimit + mUserOp.paymasterPostOpGasLimit + mUserOp.preVerificationGas;

            requiredPrefund = requiredGas * mUserOp.maxFeePerGas;
        }
    }

    /**
     * Create sender smart contract account if init code is provided.
     * @param opIndex  - The operation index.
     * @param opInfo   - The operation info.
     * @param initCode - The init code for the smart contract account.
     */
    function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;
            if (sender.code.length != 0) {
                revert FailedOp(opIndex, "AA10 sender already constructed");
            }
            uint256 _creationGas = gasleft();
            address sender1 = senderCreator().createSender{ gas: opInfo.mUserOp.verificationGasLimit }(initCode);
            setGasConsumed(sender, 0, _creationGas - gasleft());
            if (sender1 == address(0)) {
                revert FailedOp(opIndex, "AA13 initCode failed or OOG");
            }
            if (sender1 != sender) {
                revert FailedOp(opIndex, "AA14 initCode must return sender");
            }
            if (sender1.code.length == 0) {
                revert FailedOp(opIndex, "AA15 initCode must create sender");
            }
            address factory = address(bytes20(initCode[0:20]));
            emit AccountDeployed(opInfo.userOpHash, sender, factory, opInfo.mUserOp.paymaster);
        }
    }

    /// @inheritdoc IEntryPoint
    function getSenderAddress(bytes calldata initCode) public {
        address sender = senderCreator().createSender(initCode);
        revert SenderAddressResult(sender);
    }

    /**
     * Call account.validateUserOp.
     * Revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * Decrement account's deposit if needed.
     * @param opIndex         - The operation index.
     * @param op              - The user operation.
     * @param opInfo          - The operation info.
     * @param requiredPrefund - The required prefund amount.
     */
    function _validateAccountPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPrefund,
        uint256 verificationGasLimit
    )
        internal
        returns (uint256 validationData)
    {
        unchecked {
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            address sender = mUserOp.sender;
            _createSenderIfNeeded(opIndex, opInfo, op.initCode);
            address paymaster = mUserOp.paymaster;
            uint256 missingAccountFunds = 0;
            if (paymaster == address(0)) {
                uint256 bal = balanceOf(sender);
                missingAccountFunds = bal > requiredPrefund ? 0 : requiredPrefund - bal;
            }
            uint256 _verificationGas = gasleft();
            try IAccount(sender).validateUserOp{ gas: verificationGasLimit }(op, opInfo.userOpHash, missingAccountFunds)
            returns (uint256 _validationData) {
                validationData = _validationData;
                setGasConsumed(sender, 1, _verificationGas - gasleft());
            } catch {
                revert FailedOpWithRevert(opIndex, "AA23 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
            }
            if (paymaster == address(0)) {
                DepositInfo storage senderInfo = deposits[sender];
                uint256 deposit = senderInfo.deposit;
                if (requiredPrefund > deposit) {
                    revert FailedOp(opIndex, "AA21 didn't pay prefund");
                }
                senderInfo.deposit = deposit - requiredPrefund;
            }
        }
    }

    /**
     * In case the request has a paymaster:
     *  - Validate paymaster has enough deposit.
     *  - Call paymaster.validatePaymasterUserOp.
     *  - Revert with proper FailedOp in case paymaster reverts.
     *  - Decrement paymaster's deposit.
     * @param opIndex                            - The operation index.
     * @param op                                 - The user operation.
     * @param opInfo                             - The operation info.
     * @param requiredPreFund                    - The required prefund amount.
     */
    function _validatePaymasterPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPreFund
    )
        internal
        returns (bytes memory context, uint256 validationData)
    {
        unchecked {
            uint256 preGas = gasleft();
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            address paymaster = mUserOp.paymaster;
            DepositInfo storage paymasterInfo = deposits[paymaster];
            uint256 deposit = paymasterInfo.deposit;
            if (deposit < requiredPreFund) {
                revert FailedOp(opIndex, "AA31 paymaster deposit too low");
            }
            paymasterInfo.deposit = deposit - requiredPreFund;
            uint256 pmVerificationGasLimit = mUserOp.paymasterVerificationGasLimit;
            try IPaymaster(paymaster).validatePaymasterUserOp{ gas: pmVerificationGasLimit }(
                op, opInfo.userOpHash, requiredPreFund
            ) returns (bytes memory _context, uint256 _validationData) {
                context = _context;
                validationData = _validationData;
            } catch {
                revert FailedOpWithRevert(opIndex, "AA33 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
            }
            if (preGas - gasleft() > pmVerificationGasLimit) {
                revert FailedOp(opIndex, "AA36 over paymasterVerificationGasLimit");
            }
        }
    }

    /**
     * Revert if either account validationData or paymaster validationData is expired.
     * @param opIndex                 - The operation index.
     * @param validationData          - The account validationData.
     * @param paymasterValidationData - The paymaster validationData.
     * @param expectedAggregator      - The expected aggregator.
     */
    function _validateAccountAndPaymasterValidationData(
        uint256 opIndex,
        uint256 validationData,
        uint256 paymasterValidationData,
        address expectedAggregator
    )
        internal
        view
    {
        (address aggregator, bool outOfTimeRange) = _getValidationData(validationData);
        if (expectedAggregator != aggregator) {
            revert FailedOp(opIndex, "AA24 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA22 expired or not due");
        }
        // pmAggregator is not a real signature aggregator: we don't have logic to handle it as address.
        // Non-zero address means that the paymaster fails due to some signature check (which is ok only during
        // estimation).
        address pmAggregator;
        (pmAggregator, outOfTimeRange) = _getValidationData(paymasterValidationData);
        if (pmAggregator != address(0)) {
            revert FailedOp(opIndex, "AA34 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA32 paymaster expired or not due");
        }
    }

    /**
     * Parse validationData into its components.
     * @param validationData - The packed validation data (sigFailed, validAfter, validUntil).
     * @return aggregator the aggregator of the validationData
     * @return outOfTimeRange true if current time is outside the time range of this validationData.
     */
    function _getValidationData(uint256 validationData)
        internal
        view
        returns (address aggregator, bool outOfTimeRange)
    {
        if (validationData == 0) {
            return (address(0), false);
        }
        ValidationData memory data = _parseValidationData(validationData);
        // solhint-disable-next-line not-rely-on-time
        outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
        aggregator = data.aggregator;
    }

    /**
     * Validate account and paymaster (if defined) and
     * also make sure total validation doesn't exceed verificationGasLimit.
     * This method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex - The index of this userOp into the "opInfos" array.
     * @param userOp  - The userOp to validate.
     */
    function _validatePrepayment(
        uint256 opIndex,
        PackedUserOperation calldata userOp,
        UserOpInfo memory outOpInfo
    )
        internal
        returns (uint256 validationData, uint256 paymasterValidationData)
    {
        uint256 preGas = gasleft();
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);
        outOpInfo.userOpHash = getUserOpHash(userOp);

        // Validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow.
        uint256 verificationGasLimit = mUserOp.verificationGasLimit;
        uint256 maxGasValues = mUserOp.preVerificationGas | verificationGasLimit | mUserOp.callGasLimit
            | mUserOp.paymasterVerificationGasLimit | mUserOp.paymasterPostOpGasLimit | mUserOp.maxFeePerGas
            | mUserOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        uint256 requiredPreFund = _getRequiredPrefund(mUserOp);
        validationData = _validateAccountPrepayment(opIndex, userOp, outOpInfo, requiredPreFund, verificationGasLimit);

        if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
            revert FailedOp(opIndex, "AA25 invalid account nonce");
        }

        unchecked {
            if (preGas - gasleft() > verificationGasLimit) {
                revert FailedOp(opIndex, "AA26 over verificationGasLimit");
            }
        }

        bytes memory context;
        if (mUserOp.paymaster != address(0)) {
            (context, paymasterValidationData) =
                _validatePaymasterPrepayment(opIndex, userOp, outOpInfo, requiredPreFund);
        }
        unchecked {
            outOpInfo.prefund = requiredPreFund;
            outOpInfo.contextOffset = getOffsetOfMemoryBytes(context);
            outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
        }
    }

    /**
     * Process post-operation, called just after the callData is executed.
     * If a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * The excess amount is refunded to the account (or paymaster - if it was used in the request).
     * @param mode      - Whether is called from innerHandleOp, or outside (postOpReverted).
     * @param opInfo    - UserOp fields and info collected during validation.
     * @param context   - The context returned in validatePaymasterUserOp.
     * @param actualGas - The gas used so far by this user operation.
     */
    function _postExecution(
        IPaymaster.PostOpMode mode,
        UserOpInfo memory opInfo,
        bytes memory context,
        uint256 actualGas
    )
        private
        returns (uint256 actualGasCost)
    {
        uint256 preGas = gasleft();
        unchecked {
            address refundAddress;
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            uint256 gasPrice = getUserOpGasPrice(mUserOp);

            address paymaster = mUserOp.paymaster;
            if (paymaster == address(0)) {
                refundAddress = mUserOp.sender;
            } else {
                refundAddress = paymaster;
                if (context.length > 0) {
                    actualGasCost = actualGas * gasPrice;
                    if (mode != IPaymaster.PostOpMode.postOpReverted) {
                        try IPaymaster(paymaster).postOp{ gas: mUserOp.paymasterPostOpGasLimit }(
                            mode, context, actualGasCost, gasPrice
                        ) {
                            // solhint-disable-next-line no-empty-blocks
                        } catch {
                            bytes memory reason = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                            revert PostOpReverted(reason);
                        }
                    }
                }
            }
            actualGas += preGas - gasleft();

            // Calculating a penalty for unused execution gas
            {
                uint256 executionGasLimit = mUserOp.callGasLimit + mUserOp.paymasterPostOpGasLimit;
                uint256 executionGasUsed = actualGas - opInfo.preOpGas;
                // this check is required for the gas used within EntryPoint and not covered by explicit gas limits
                if (executionGasLimit > executionGasUsed) {
                    uint256 unusedGas = executionGasLimit - executionGasUsed;
                    uint256 unusedGasPenalty = (unusedGas * PENALTY_PERCENT) / 100;
                    actualGas += unusedGasPenalty;
                }
            }

            actualGasCost = actualGas * gasPrice;
            uint256 prefund = opInfo.prefund;
            if (prefund < actualGasCost) {
                if (mode == IPaymaster.PostOpMode.postOpReverted) {
                    actualGasCost = prefund;
                    emitPrefundTooLow(opInfo);
                    emitUserOperationEvent(opInfo, false, actualGasCost, actualGas);
                } else {
                    assembly ("memory-safe") {
                        mstore(0, INNER_REVERT_LOW_PREFUND)
                        revert(0, 32)
                    }
                }
            } else {
                uint256 refund = prefund - actualGasCost;
                _incrementDeposit(refundAddress, refund);
                bool success = mode == IPaymaster.PostOpMode.opSucceeded;
                emitUserOperationEvent(opInfo, success, actualGasCost, actualGas);
            }
        } // unchecked
    }

    /**
     * The gas price this UserOp agrees to pay.
     * Relayer/block builder might submit the TX with higher priorityFee, but the user should not.
     * @param mUserOp - The userOp to get the gas price from.
     */
    function getUserOpGasPrice(MemoryUserOp memory mUserOp) internal view returns (uint256) {
        unchecked {
            uint256 maxFeePerGas = mUserOp.maxFeePerGas;
            uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    /**
     * The offset of the given bytes in memory.
     * @param data - The bytes to get the offset of.
     */
    function getOffsetOfMemoryBytes(bytes memory data) internal pure returns (uint256 offset) {
        assembly {
            offset := data
        }
    }

    /**
     * The bytes in memory at the given offset.
     * @param offset - The offset to get the bytes from.
     */
    function getMemoryBytesFromOffset(uint256 offset) internal pure returns (bytes memory data) {
        assembly ("memory-safe") {
            data := offset
        }
    }

    /// @inheritdoc IEntryPoint
    function delegateAndRevert(address target, bytes calldata data) external {
        (bool success, bytes memory ret) = target.delegatecall(data);
        revert DelegateAndRevert(success, ret);
    }
}

// node_modules/@ERC4337/account-abstraction/contracts/core/EntryPointSimulations.sol

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

/*
 * This contract inherits the EntryPoint and extends it with the view-only methods that are executed by
 * the bundler in order to check UserOperation validity and estimate its gas consumption.
 * This contract should never be deployed on-chain and is only used as a parameter for the "eth_call" request.
 */
contract EntryPointSimulations is EntryPoint, IEntryPointSimulations {
    // solhint-disable-next-line var-name-mixedcase
    AggregatorStakeInfo private NOT_AGGREGATED = AggregatorStakeInfo(address(0), StakeInfo(0, 0));

    SenderCreator private _senderCreator;

    function initSenderCreator() internal virtual {
        //this is the address of the first contract created with CREATE by this address.
        address createdObj = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01")))));
        _senderCreator = SenderCreator(createdObj);
    }

    function senderCreator() internal view virtual override returns (SenderCreator) {
        // return the same senderCreator as real EntryPoint.
        // this call is slightly (100) more expensive than EntryPoint's access to immutable member
        return _senderCreator;
    }

    /**
     * simulation contract should not be deployed, and specifically, accounts should not trust
     * it as entrypoint, since the simulation functions don't check the signatures
     */
    constructor() {
        // THIS CONTRACT SHOULD NOT BE DEPLOYED
        // however, the line of code below is commented to allow this entryPoint to be used in fork tests
        // require(block.number < 100, "should not be deployed");
    }

    /// @inheritdoc IEntryPointSimulations
    function simulateValidation(PackedUserOperation calldata userOp) external returns (ValidationResult memory) {
        UserOpInfo memory outOpInfo;

        _simulationOnlyValidations(userOp);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, userOp, outOpInfo);
        StakeInfo memory paymasterInfo = _getStakeInfo(outOpInfo.mUserOp.paymaster);
        StakeInfo memory senderInfo = _getStakeInfo(outOpInfo.mUserOp.sender);
        StakeInfo memory factoryInfo;
        {
            bytes calldata initCode = userOp.initCode;
            address factory = initCode.length >= 20 ? address(bytes20(initCode[0:20])) : address(0);
            factoryInfo = _getStakeInfo(factory);
        }

        address aggregator = address(uint160(validationData));
        ReturnInfo memory returnInfo = ReturnInfo(
            outOpInfo.preOpGas,
            outOpInfo.prefund,
            validationData,
            paymasterValidationData,
            getMemoryBytesFromOffset(outOpInfo.contextOffset)
        );

        AggregatorStakeInfo memory aggregatorInfo = NOT_AGGREGATED;
        if (uint160(aggregator) != SIG_VALIDATION_SUCCESS && uint160(aggregator) != SIG_VALIDATION_FAILED) {
            aggregatorInfo = AggregatorStakeInfo(aggregator, _getStakeInfo(aggregator));
        }
        return ValidationResult(returnInfo, senderInfo, factoryInfo, paymasterInfo, aggregatorInfo);
    }

    /// @inheritdoc IEntryPointSimulations
    function simulateHandleOp(
        PackedUserOperation calldata op,
        address target,
        bytes calldata targetCallData
    )
        external
        nonReentrant
        returns (ExecutionResult memory)
    {
        UserOpInfo memory opInfo;
        _simulationOnlyValidations(op);
        (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(0, op, opInfo);

        uint256 paid = _executeUserOp(0, op, opInfo);
        bool targetSuccess;
        bytes memory targetResult;
        if (target != address(0)) {
            (targetSuccess, targetResult) = target.call(targetCallData);
        }
        return
            ExecutionResult(opInfo.preOpGas, paid, validationData, paymasterValidationData, targetSuccess, targetResult);
    }

    function _simulationOnlyValidations(PackedUserOperation calldata userOp) internal {
        //initialize senderCreator(). we can't rely on constructor
        initSenderCreator();

        try this._validateSenderAndPaymaster(userOp.initCode, userOp.sender, userOp.paymasterAndData) {
            // solhint-disable-next-line no-empty-blocks
        } catch Error(string memory revertReason) {
            if (bytes(revertReason).length != 0) {
                revert FailedOp(0, revertReason);
            }
        }
    }

    /**
     * Called only during simulation.
     * This function always reverts to prevent warm/cold storage differentiation in simulation vs execution.
     * @param initCode         - The smart account constructor code.
     * @param sender           - The sender address.
     * @param paymasterAndData - The paymaster address (followed by other params, ignored by this method)
     */
    function _validateSenderAndPaymaster(
        bytes calldata initCode,
        address sender,
        bytes calldata paymasterAndData
    )
        external
        view
    {
        if (initCode.length == 0 && sender.code.length == 0) {
            // it would revert anyway. but give a meaningful message
            revert("AA20 account not deployed");
        }
        if (paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(paymasterAndData[0:20]));
            if (paymaster.code.length == 0) {
                // It would revert anyway. but give a meaningful message.
                revert("AA30 paymaster not deployed");
            }
        }
        // always revert
        revert("");
    }

    //make sure depositTo cost is more than normal EntryPoint's cost,
    // to mitigate DoS vector on the bundler
    // empiric test showed that without this wrapper, simulation depositTo costs less..
    function depositTo(address account) public payable override(IStakeManager, StakeManager) {
        unchecked {
            // silly code, to waste some gas to make sure depositTo is always little more
            // expensive than on-chain call
            uint256 x = 1;
            while (x < 5) {
                x++;
            }
            StakeManager.depositTo(account);
        }
    }
}

// node_modules/@rhinestone/modulekit/src/external/ERC4337.sol

/* solhint-disable no-unused-import */

/*//////////////////////////////////////////////////////////////
                            USEROP
//////////////////////////////////////////////////////////////*/

/*//////////////////////////////////////////////////////////////
                            ENTRYPOINT
//////////////////////////////////////////////////////////////*/

/*//////////////////////////////////////////////////////////////
                            VALIDATION
//////////////////////////////////////////////////////////////*/

/*//////////////////////////////////////////////////////////////
                            INTERFACES
//////////////////////////////////////////////////////////////*/

// node_modules/@rhinestone/modulekit/src/module-bases/interfaces/IPolicy.sol

// solhint-disable no-unused-import

type ConfigId is bytes32;

/**
 * IPolicy are external contracts that enforce policies / permission on 4337/7579 executions
 * Since it's not the account calling into this contract, and check functions are called during the
 * ERC4337 validation
 * phase, IPolicy implementations MUST follow ERC4337 storage and opcode restrictions
 * A recommend storage layout to store policy related data:
 *      mapping(id   =>   msg.sender   =>   userOp.sender(account) => state)
 *                        ^ smartSession    ^ smart account (associated storage)
 */
interface IPolicy_1 is IERC165_1, IModule {
    function isInitialized(address account, ConfigId configId) external view returns (bool);
    function isInitialized(address account, address mulitplexer, ConfigId configId) external view returns (bool);

    /**
     * This function may be called by the multiplexer (SmartSessions) without deinitializing first.
     * Policies MUST overwrite the current state when this happens
     */
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external;
}

/**
 * IUserOpPolicy is a policy that enforces restrictions on user operations. It is called during the
 * validation phase
 * of the ERC4337 execution.
 * Use this policy to enforce restrictions on user operations (userOp.gas, Time based restrictions).
 * The checkUserOpPolicy function should return a uint256 value that represents the policy's
 * decision.
 * The policy's decision should be one of the following:
 * - VALIDATION_SUCCESS: The user operation is allowed.
 * - VALIDATION_FAILED: The user operation is not allowed.
 */
interface IUserOpPolicy is IPolicy_1 {
    function checkUserOpPolicy(ConfigId id, PackedUserOperation calldata userOp) external returns (uint256);
}

/**
 * IActionPolicy is a policy that enforces restrictions on actions. It is called during the
 * validation phase
 * of the ERC4337 execution.
 * ERC7579 accounts natively support batched executions. So in one userOp, multiple actions can be
 * executed.
 * SmartSession will destruct the execution batch, and call the policy for each action, if the
 * policy is installed for
 * the actionId for the account.
 * Use this policy to enforce restrictions on individual actions (i.e. transfers, approvals, etc).
 * The checkAction function should return a uint256 value that represents the policy's decision.
 * The policy's decision should be one of the following:
 * - VALIDATION_SUCCESS: The action is allowed.
 * - VALIDATION_FAILED: The action is not allowed.
 */
interface IActionPolicy is IPolicy_1 {
    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        returns (uint256);
}

/**
 * I1271Policy is a policy that enforces restrictions on 1271 signed actions. It is called during an
 * ERC1271 signature
 * validation
 */
interface I1271Policy is IPolicy_1 {
    // request sender is probably protocol, so can introduce policies based on it.
    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bool);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579ValidatorBase.sol

abstract contract ERC7579ValidatorBase is ERC7579ModuleBase {
    type ValidationData is uint256;

    ValidationData internal constant VALIDATION_SUCCESS = ValidationData.wrap(0);
    ValidationData internal constant VALIDATION_FAILED = ValidationData.wrap(1);
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAILED = 0xFFFFFFFF;

    /**
     * Helper to pack the return value for validateUserOp, when not using an aggregator.
     * @param sigFailed  - True for signature failure, false for success.
     * @param validUntil - Last timestamp this UserOperation is valid (or zero for
     * infinite).
     * @param validAfter - First timestamp this UserOperation is valid.
     */
    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    )
        internal
        pure
        returns (ValidationData)
    {
        return ValidationData.wrap(_packValidationData_1(sigFailed, validUntil, validAfter));
    }

    function _unpackValidationData(ValidationData _packedData)
        internal
        pure
        returns (bool sigFailed, uint48 validUntil, uint48 validAfter)
    {
        uint256 packedData = ValidationData.unwrap(_packedData);
        sigFailed = (packedData & 1) == 1;
        validUntil = uint48((packedData >> 160) & ((1 << 48) - 1));
        validAfter = uint48((packedData >> (160 + 48)) & ((1 << 48) - 1));
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        virtual
        returns (ValidationData);

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        virtual
        returns (bytes4);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579PolicyBase.sol

abstract contract ERC7579PolicyBase is ERC7579ModuleBase, IPolicy_1 {
    function initializeWithMultiplexer(address account, ConfigId configId, bytes calldata initData) external virtual;
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC1271Policy.sol

abstract contract ERC1271Policy is ERC7579PolicyBase, I1271Policy {
    function check1271SignedAction(
        ConfigId id,
        address requestSender,
        address account,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        virtual
        returns (bool);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579ActionPolicy.sol

abstract contract ERC7579ActionPolicy is ERC7579PolicyBase, IActionPolicy {
    function checkAction(
        ConfigId id,
        address account,
        address target,
        uint256 value,
        bytes calldata data
    )
        external
        virtual
        returns (uint256);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579HybridValidatorBase.sol

/* solhint-disable no-unused-import */

/// @notice Base contract for hybrid validators, which are both stateful and stateless.
abstract contract ERC7579HybridValidatorBase is ERC7579ValidatorBase, ERC7579StatelessValidatorBase { }

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579UserOpPolicy.sol

abstract contract ERC7579UserOpPolicy is ERC7579PolicyBase, IUserOpPolicy {
    function checkUserOp(ConfigId id, PackedUserOperation calldata userOp) external virtual returns (uint256);
}

// node_modules/@rhinestone/modulekit/src/module-bases/ERC7579HookDestruct.sol

uint256 constant EXECUSEROP_OFFSET = 164;
uint256 constant EXEC_OFFSET = 100;
uint256 constant INSTALL_OFFSET = 132;

abstract contract ERC7579HookDestruct is IHook, ERC7579ModuleBase, TrustedForwarder {
    error HookInvalidSelector();
    error InvalidCallType();

    /*//////////////////////////////////////////////////////////////////////////
                                CALLDATA DECODING
    //////////////////////////////////////////////////////////////////////////*/

    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        external
        virtual
        override
        returns (bytes memory hookData)
    {
        bytes4 selector = bytes4(msgData[0:4]);

        if (selector == IAccountExecute.executeUserOp.selector) {
            uint256 offset = uint256(bytes32(msgData[EXECUSEROP_OFFSET:EXECUSEROP_OFFSET + 32])) + 68;
            uint256 paramLen = uint256(bytes32(msgData[offset:offset + 32]));
            offset += 32;
            bytes calldata _msgData = msgData[offset:offset + paramLen];
            return _decodeCallData(msgSender, msgValue, _msgData);
        } else {
            return _decodeCallData(msgSender, msgValue, msgData);
        }
    }

    function _decodeCallData(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        internal
        returns (bytes memory hookData)
    {
        bytes4 selector = bytes4(msgData[0:4]);
        if (selector == IERC7579Account.execute.selector) {
            return _handle4337Executions(msgSender, msgData);
        } else if (selector == IERC7579Account.executeFromExecutor.selector) {
            return _handleExecutorExecutions(msgSender, msgData);
        } else if (selector == IERC7579Account.installModule.selector) {
            uint256 paramLen = msgData.length > INSTALL_OFFSET
                ? uint256(bytes32(msgData[INSTALL_OFFSET - 32:INSTALL_OFFSET]))
                : uint256(0);
            bytes calldata initData =
                msgData.length > INSTALL_OFFSET ? msgData[INSTALL_OFFSET:INSTALL_OFFSET + paramLen] : msgData[0:0];
            uint256 moduleType = uint256(bytes32(msgData[4:36]));
            address module = address(bytes20((msgData[48:68])));
            return onInstallModule(_getAccount(), msgSender, moduleType, module, initData);
        } else if (selector == IERC7579Account.uninstallModule.selector) {
            uint256 paramLen = msgData.length > INSTALL_OFFSET
                ? uint256(bytes32(msgData[INSTALL_OFFSET - 32:INSTALL_OFFSET]))
                : uint256(0);
            bytes calldata initData =
                msgData.length > INSTALL_OFFSET ? msgData[INSTALL_OFFSET:INSTALL_OFFSET + paramLen] : msgData[0:0];

            uint256 moduleType = uint256(bytes32(msgData[4:36]));
            address module = address(bytes20((msgData[48:68])));

            return onUninstallModule(_getAccount(), msgSender, moduleType, module, initData);
        } else {
            return onUnknownFunction(_getAccount(), msgSender, msgValue, msgData);
        }
    }

    function _handle4337Executions(
        address msgSender,
        bytes calldata msgData
    )
        internal
        returns (bytes memory hookData)
    {
        uint256 paramLen = uint256(bytes32(msgData[EXEC_OFFSET - 32:EXEC_OFFSET]));
        bytes calldata encodedExecutions = msgData[EXEC_OFFSET:EXEC_OFFSET + paramLen];

        ModeCode mode = ModeCode.wrap(bytes32(msgData[4:36]));
        CallType calltype = ModeLib.getCallType(mode);

        if (calltype == CALLTYPE_SINGLE) {
            (address to, uint256 value, bytes calldata callData) = ExecutionLib.decodeSingle(encodedExecutions);
            return onExecute(_getAccount(), msgSender, to, value, callData);
        } else if (calltype == CALLTYPE_BATCH) {
            Execution[] calldata execs = ExecutionLib.decodeBatch(encodedExecutions);
            return onExecuteBatch(_getAccount(), msgSender, execs);
        } else if (calltype == CALLTYPE_DELEGATECALL) {
            address to = address(bytes20(encodedExecutions[0:20]));
            bytes calldata callData = encodedExecutions[20:];
            return onExecuteDelegateCall(_getAccount(), msgSender, to, callData);
        } else {
            revert InvalidCallType();
        }
    }

    function _handleExecutorExecutions(
        address msgSender,
        bytes calldata msgData
    )
        internal
        returns (bytes memory hookData)
    {
        uint256 paramLen = uint256(bytes32(msgData[EXEC_OFFSET - 32:EXEC_OFFSET]));
        bytes calldata encodedExecutions = msgData[EXEC_OFFSET:EXEC_OFFSET + paramLen];

        ModeCode mode = ModeCode.wrap(bytes32(msgData[4:36]));
        CallType calltype = ModeLib.getCallType(mode);

        if (calltype == CALLTYPE_SINGLE) {
            (address to, uint256 value, bytes calldata callData) = ExecutionLib.decodeSingle(encodedExecutions);
            return onExecuteFromExecutor(_getAccount(), msgSender, to, value, callData);
        } else if (calltype == CALLTYPE_BATCH) {
            Execution[] calldata execs = ExecutionLib.decodeBatch(encodedExecutions);
            return onExecuteBatchFromExecutor(_getAccount(), msgSender, execs);
        } else if (calltype == CALLTYPE_DELEGATECALL) {
            address to = address(bytes20(encodedExecutions[0:20]));
            bytes calldata callData = encodedExecutions[20:];
            return onExecuteDelegateCallFromExecutor(_getAccount(), msgSender, to, callData);
        } else {
            revert InvalidCallType();
        }
    }

    function postCheck(bytes calldata hookData) external virtual override {
        onPostCheck(_getAccount(), hookData);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     EXECUTION
    //////////////////////////////////////////////////////////////////////////*/

    function onExecute(
        address account,
        address msgSender,
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onExecuteBatch(
        address account,
        address msgSender,
        Execution[] calldata
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onExecuteDelegateCall(
        address account,
        address msgSender,
        address target,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onExecuteFromExecutor(
        address account,
        address msgSender,
        address target,
        uint256 value,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onExecuteBatchFromExecutor(
        address account,
        address msgSender,
        Execution[] calldata
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onExecuteDelegateCallFromExecutor(
        address account,
        address msgSender,
        address target,
        bytes calldata callData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    function onInstallModule(
        address account,
        address msgSender,
        uint256 moduleType,
        address module,
        bytes calldata initData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    function onUninstallModule(
        address account,
        address msgSender,
        uint256 moduleType,
        address module,
        bytes calldata deInitData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    /*//////////////////////////////////////////////////////////////////////////
                                UNKNOWN FUNCTION
    //////////////////////////////////////////////////////////////////////////*/

    function onUnknownFunction(
        address account,
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        internal
        virtual
        returns (bytes memory hookData)
    { }

    /*//////////////////////////////////////////////////////////////////////////
                                     POSTCHECK
    //////////////////////////////////////////////////////////////////////////*/

    function onPostCheck(address account, bytes calldata hookData) internal virtual { }
}

// node_modules/@rhinestone/modulekit/src/Modules.sol

/* solhint-disable no-unused-import */

/*//////////////////////////////////////////////////////////////
                          INTERFACES
//////////////////////////////////////////////////////////////*/

/*//////////////////////////////////////////////////////////////
                            BASES
//////////////////////////////////////////////////////////////*/

// Core

// Validators

// Executors

// Hooks

// Fallbacks

// Misc

// Policies

/*//////////////////////////////////////////////////////////////
                            UTIL
//////////////////////////////////////////////////////////////*/

// src/OwnableValidator/OwnableValidator.sol

uint256 constant TYPE_STATELESS_VALIDATOR = 7;
/**
 * @title OwnableValidator
 * @dev Module that allows users to designate EOA owners that can validate transactions using a
 * threshold
 * @author Rhinestone
 */

contract OwnableValidator is ERC7579ValidatorBase {
    using LibSort for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;

    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    event ModuleInitialized(address indexed account);
    event ModuleUninitialized(address indexed account);
    event ThresholdSet(address indexed account, uint256 threshold);
    event OwnerAdded(address indexed account, address indexed owner);
    event OwnerRemoved(address indexed account, address indexed owner);

    error ThresholdNotSet();
    error InvalidThreshold();
    error NotSortedAndUnique();
    error MaxOwnersReached();
    error InvalidOwner(address owner);
    error CannotRemoveOwner();

    // maximum number of owners per account
    uint256 constant MAX_OWNERS = 32;

    // account => owners
    SentinelList4337Lib.SentinelList owners;
    // account => threshold
    mapping(address account => uint256) public threshold;
    // account => ownerCount
    mapping(address => uint256) public ownerCount;

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initializes the module with the threshold and owners
     * @dev data is encoded as follows: abi.encode(threshold, owners)
     *
     * @param data encoded data containing the threshold and owners
     */
    function onInstall(bytes calldata data) external override {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            revert NotSortedAndUnique();
        }

        // make sure the threshold is set
        if (_threshold == 0) {
            revert ThresholdNotSet();
        }

        // make sure the threshold is less than the number of owners
        uint256 ownersLength = _owners.length;
        if (ownersLength < _threshold) {
            revert InvalidThreshold();
        }

        // cache the account address
        address account = msg.sender;

        // set threshold
        threshold[account] = _threshold;

        // check if max owners is reached
        if (ownersLength > MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // set owner count
        ownerCount[account] = ownersLength;

        // initialize the owner list
        owners.init(account);

        // add owners to the list
        for (uint256 i = 0; i < ownersLength; i++) {
            address _owner = _owners[i];
            if (_owner == address(0)) {
                revert InvalidOwner(_owner);
            }
            owners.push(account, _owner);
            emit OwnerAdded(account, _owner);
        }

        emit ModuleInitialized(account);
    }

    /**
     * Handles the uninstallation of the module and clears the threshold and owners
     * @dev the data parameter is not used
     */
    function onUninstall(bytes calldata) external override {
        // cache the account address
        address account = msg.sender;

        // clear the owners
        address[] memory ownersArray;
        (ownersArray,) = owners.getEntriesPaginated(account, SENTINEL, MAX_OWNERS);
        for (uint256 i = 0; i < ownersArray.length; i++) {
            address owner = ownersArray[i];
            // remove the owner from the list
            owners.pop(account, SENTINEL, owner);
            emit OwnerRemoved(account, owner);
        }

        // remove the threshold
        threshold[account] = 0;

        // remove the owner count
        ownerCount[account] = 0;

        emit ModuleUninitialized(account);
    }

    /**
     * Checks if the module is initialized
     *
     * @param smartAccount address of the smart account
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) public view returns (bool) {
        return threshold[smartAccount] != 0;
    }

    /**
     * Sets the threshold for the account
     * @dev the function will revert if the module is not initialized
     *
     * @param _threshold uint256 threshold to set
     */
    function setThreshold(uint256 _threshold) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // make sure that the threshold is set
        if (_threshold == 0) {
            revert InvalidThreshold();
        }

        // make sure the threshold is less than the number of owners
        if (ownerCount[account] < _threshold) {
            revert InvalidThreshold();
        }

        // set the threshold
        threshold[account] = _threshold;

        emit ThresholdSet(account, _threshold);
    }

    /**
     * Adds an owner to the account
     * @dev will revert if the owner is already added
     *
     * @param owner address of the owner to add
     */
    function addOwner(address owner) external {
        // cache the account address
        address account = msg.sender;
        // check if the module is initialized and revert if it is not
        if (!isInitialized(account)) revert NotInitialized(account);

        // revert if the owner is address(0)
        if (owner == address(0)) {
            revert InvalidOwner(owner);
        }

        // check if max owners is reached
        if (ownerCount[account] >= MAX_OWNERS) {
            revert MaxOwnersReached();
        }

        // increment the owner count
        ownerCount[account]++;

        // add the owner to the linked list
        owners.push(account, owner);

        emit OwnerAdded(account, owner);
    }

    /**
     * Removes an owner from the account
     * @dev will revert if the owner is not added or the previous owner is invalid
     *
     * @param prevOwner address of the previous owner
     * @param owner address of the owner to remove
     */
    function removeOwner(address prevOwner, address owner) external {
        // cache the account address
        address account = msg.sender;

        // check if an owner can be removed
        if (ownerCount[account] == threshold[account]) {
            // if the owner count is equal to the threshold, revert
            // this means that removing an owner would make the threshold unreachable
            revert CannotRemoveOwner();
        }

        // remove the owner
        owners.pop(account, prevOwner, owner);

        // decrement the owner count
        ownerCount[account]--;

        emit OwnerRemoved(account, owner);
    }

    /**
     * Returns the owners of the account
     *
     * @param account address of the account
     *
     * @return ownersArray array of owners
     */
    function getOwners(address account) external view returns (address[] memory ownersArray) {
        // get the owners from the linked list
        (ownersArray,) = owners.getEntriesPaginated(account, SENTINEL, MAX_OWNERS);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Validates a user operation
     *
     * @param userOp PackedUserOperation struct containing the UserOperation
     * @param userOpHash bytes32 hash of the UserOperation
     *
     * @return ValidationData the UserOperation validation result
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        override
        returns (ValidationData)
    {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(userOp.sender, userOpHash, userOp.signature);

        // return the result
        if (isValid) {
            return VALIDATION_SUCCESS;
        }
        return VALIDATION_FAILED;
    }

    /**
     * Validates an ERC-1271 signature with the sender
     *
     * @param hash bytes32 hash of the data
     * @param data bytes data containing the signatures
     *
     * @return bytes4 EIP1271_SUCCESS if the signature is valid, EIP1271_FAILED otherwise
     */
    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata data
    )
        external
        view
        override
        returns (bytes4)
    {
        // validate the signature with the config
        bool isValid = _validateSignatureWithConfig(msg.sender, hash, data);

        // return the result
        if (isValid) {
            return EIP1271_SUCCESS;
        }
        return EIP1271_FAILED;
    }

    /**
     * Validates a signature with the data (stateless validation)
     *
     * @param hash bytes32 hash of the data
     * @param signature bytes data containing the signatures
     * @param data bytes data containing the data
     *
     * @return bool true if the signature is valid, false otherwise
     */
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata signature,
        bytes calldata data
    )
        external
        view
        returns (bool)
    {
        // decode the threshold and owners
        (uint256 _threshold, address[] memory _owners) = abi.decode(data, (uint256, address[]));

        // check that owners are sorted and uniquified
        if (!_owners.isSortedAndUniquified()) {
            return false;
        }

        // check that threshold is set
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers =
            CheckSignatures.recoverNSignatures(ECDSA.toEthSignedMessageHash(hash), signature, _threshold);

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            (bool found,) = _owners.searchSorted(signers[i]);
            if (found) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    function _validateSignatureWithConfig(
        address account,
        bytes32 hash,
        bytes calldata data
    )
        internal
        view
        returns (bool)
    {
        // get the threshold and check that its set
        uint256 _threshold = threshold[account];
        if (_threshold == 0) {
            return false;
        }

        // recover the signers from the signatures
        address[] memory signers =
            CheckSignatures.recoverNSignatures(ECDSA.toEthSignedMessageHash(hash), data, _threshold);

        // sort and uniquify the signers to make sure a signer is not reused
        signers.sort();
        signers.uniquifySorted();

        // check if the signers are owners
        uint256 validSigners;
        uint256 signersLength = signers.length;
        for (uint256 i = 0; i < signersLength; i++) {
            if (owners.contains(account, signers[i])) {
                validSigners++;
            }
        }

        // check if the threshold is met and return the result
        if (validSigners >= _threshold) {
            // if the threshold is met, return true
            return true;
        }
        // if the threshold is not met, return false
        return false;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Returns the type of the module
     *
     * @param typeID type of the module
     *
     * @return true if the type is a module type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_STATELESS_VALIDATOR;
    }

    /**
     * Returns the name of the module
     *
     * @return name of the module
     */
    function name() external pure virtual returns (string memory) {
        return "OwnableValidator";
    }

    /**
     * Returns the version of the module
     *
     * @return version of the module
     */
    function version() external pure virtual returns (string memory) {
        return "1.0.0";
    }
}
