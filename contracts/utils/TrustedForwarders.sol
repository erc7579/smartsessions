// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

// Credits: @rhinestone @zeroknots

abstract contract TrustedForwarderWithId {
    
    // id => account => trustedForwarder
    // This approach with Id allows setting various Trusted Forwarders for the same account
    // It can in theory be required when the same sub-module (that inherits this) is used with 
    // different multiplexers on one account. 
    // For example, same SignerValidator is used via PermissionsManager and some SignerMultiplexer
    // id is the config id of the sub-module
    // 
    // However, it adds one SSTORE for every activation of a submodule.
    // To reduce SSTORE's, the id can be removed. In this case the submodule will only 
    // be usable with one trusted forwarder (multiplexer) per smart account.
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
