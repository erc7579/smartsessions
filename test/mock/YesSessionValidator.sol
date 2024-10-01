// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/DataTypes.sol";
import { ISessionValidator } from "contracts/interfaces/ISessionValidator.sol";

contract YesSessionValidator is ISessionValidator {
    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR;
    }

    function isInitialized(address multiplexer, address account, ConfigId id) external view returns (bool) {
        return true;
    }

    function isInitialized(address account) external view returns (bool) {
        return true;
    }

    function isInitialized(address multiplexer, address account) external view returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        view
        override
        returns (bool validSig)
    {
        return true;
    }

    /**
     * @dev This function is called by the smart account during installation of the module
     * @param data arbitrary data that may be required on the module during `onInstall`
     * initialization
     *
     * MUST revert on error (i.e. if module is already enabled)
     */
    function onInstall(bytes calldata data) external { }

    /**
     * @dev This function is called by the smart account during uninstallation of the module
     * @param data arbitrary data that may be required on the module during `onUninstall`
     * de-initialization
     *
     * MUST revert on error
     */
    function onUninstall(bytes calldata data) external { }
}
