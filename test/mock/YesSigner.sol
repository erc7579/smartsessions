// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

contract YesSigner is ISignerValidator /*, TrustedForwarderWithId*/ {
    // can use sender as argument here as the method is view
    // so even external calls with arbitrary sender can not break things
    function checkSignature(
        bytes32 signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        override
        returns (bytes4)
    {
        return 0x1626ba7e;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return true;
    }

    function onInstall(bytes calldata data) external { }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }
}
