// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { ITrustedForwarder } from "contracts/utils/interfaces/ITrustedForwarder.sol";

// Credits: @rhinestone @zeroknots

// !WARNING: One should be careful with the TrustedForwarder as calldata is
// appended with 2 extra addresses, so should have this in mind when parsing calldata
// in the submodule that is TrustedForwarder

// ** TrustedForwarderWithId **
//
// This approach with Id allows setting various Trusted Forwarders for the same account
// It can in theory be required when the same sub-module (that inherits this) is used with
// different multiplexers on one account.
// For example, same SignerValidator is used via PermissionsManager and some SignerMultiplexer
// id is the config id of the sub-module
//
// However, it adds one SSTORE for every activation of a submodule.
// To reduce SSTORE's, the id can be removed. In this case the submodule will only
// be usable with one trusted forwarder (multiplexer) per smart account. See TrusteForwarder below

abstract contract TrustedForwarderWithId is ITrustedForwarder {
    // id => account => trustedForwarder
    mapping(bytes32 id => mapping(address account => address)) public trustedForwarder;

    /**
     * Set the trusted forwarder for an account.
     * Should be called by the smart account itself
     *
     * @param forwarder The address of the trusted forwarder
     */
    function setTrustedForwarder(address forwarder, bytes32 id) external {
        trustedForwarder[id][msg.sender] = forwarder;
    }

    /**
     * Clear the trusted forwarder for an account
     */
    function clearTrustedForwarder(bytes32 id) public {
        trustedForwarder[id][msg.sender] = address(0);
    }

    /**
     * Check if a forwarder is trusted for an account
     *
     * @param forwarder The address of the forwarder
     * @param account The address of the account
     *
     * @return true if the forwarder is trusted for the account
     */
    function isTrustedForwarder(address forwarder, address account, bytes32 id) public view returns (bool) {
        return forwarder == trustedForwarder[id][account];
    }

    /**
     * Get the sender of the transaction
     *
     * @return account the sender of the transaction
     */
    function _getAccount(bytes32 id) internal view returns (address account) {
        account = msg.sender;
        address _account;
        address forwarder;
        if (msg.data.length >= 40) {
            assembly {
                _account := shr(96, calldataload(sub(calldatasize(), 20)))
                forwarder := shr(96, calldataload(sub(calldatasize(), 40)))
            }
            if (forwarder == msg.sender && isTrustedForwarder(forwarder, _account, id)) {
                account = _account;
            }
        }
    }

    // IERC165 Id = 0x41f02a24
    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        return interfaceId == type(ITrustedForwarder).interfaceId;
    }
}

// ** TrustedForwarder **
//
// This approach allows setting only one Trusted Forwarder for the same Smart Account per sub-module
// It ignores the id, however it doesn't check if the same address has already been set as Trusted Forwarder
// So ensure you are checking this in the caller contract to avoid excess SSTORE's

abstract contract TrustedForwarder is ITrustedForwarder {
    // account => trustedForwarder
    mapping(address account => address) public trustedForwarder;

    /**
     * Set the trusted forwarder for an account.
     * Should be called by the smart account itself
     *
     * @param forwarder The address of the trusted forwarder
     */
    function setTrustedForwarder(address forwarder, bytes32) external {
        trustedForwarder[msg.sender] = forwarder;
    }

    /**
     * Clear the trusted forwarder for an account
     */
    function clearTrustedForwarder(bytes32) public {
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
    function isTrustedForwarder(address forwarder, address account, bytes32) external view returns (bool) {
        return _isTrustedForwarder(forwarder, account);
    }

    function _isTrustedForwarder(address forwarder, address account) internal view returns (bool) {
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
            assembly {
                _account := shr(96, calldataload(sub(calldatasize(), 20)))
                forwarder := shr(96, calldataload(sub(calldatasize(), 40)))
            }
            if (forwarder == msg.sender && _isTrustedForwarder(forwarder, _account)) {
                account = _account;
            }
        }
    }

    // IERC165 Id = 0x41f02a24
    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
        return interfaceId == type(ITrustedForwarder).interfaceId;
    }
}
