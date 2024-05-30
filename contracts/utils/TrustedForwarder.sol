// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

// Credits: @rhinestone @zeroknots

abstract contract TrustedForwarder {
    // account => trustedForwarder
    mapping(bytes32 id => mapping(address account => address)) public trustedForwarder;

    /**
     * Set the trusted forwarder for an account.
     * Should be called by the smart account itself
     *
     * @param forwarder The address of the trusted forwarder
     */
    function setTrustedForwarder(bytes32 id, address forwarder) external {
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
    function isTrustedForwarder(address forwarder, bytes32 id, address account) public view returns (bool) {
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
            if (forwarder == msg.sender && isTrustedForwarder(forwarder, id, _account)) {
                account = _account;
            }
        }
    }
}
