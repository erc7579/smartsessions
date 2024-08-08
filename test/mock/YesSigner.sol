// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { SessionId, ISigner } from "contracts/interfaces/ISigner.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

contract YesSigner is ISigner /*, TrustedForwarderWithId*/ {
    function onInstall(bytes calldata data) external { }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }

    function isInitialized(address account, SessionId id) external view returns (bool) {
        return true;
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view returns (bool) {
        return true;
    }

    function isInitialized(address account) external view returns (bool) {
        return true;
    }

    function isInitialized(address multiplexer, address account) external view returns (bool) {
        return true;
    }

    function supportsInterface(bytes4 interfaceID) external view override returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        override
        returns (bool validSig)
    {
        return true;
    }
}
