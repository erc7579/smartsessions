// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import "contracts/DataTypes.sol";
import { ISessionValidator } from "contracts/interfaces/ISessionValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

contract SimpleSessionValidator is ISessionValidator {
    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        view
        returns (bool validSig)
    {
        address owner = address(bytes20(data[0:20]));
        address recovered;
        recovered = ECDSA.recover(hash, sig);
        if (owner == recovered) {
            return true;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        recovered = ECDSA.recover(ethHash, sig);
        if (owner == recovered) {
            return true;
        }
        return false;
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == ERC7579_MODULE_TYPE_STATELESS_VALIDATOR;
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

    function isInitialized(address account) external view returns (bool) {
        return true;
    }
}
