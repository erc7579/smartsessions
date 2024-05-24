// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { ERC7579HookBase } from "modulekit/Modules.sol";

contract HookTemplate is ERC7579HookBase {
    /*//////////////////////////////////////////////////////////////////////////
                            CONSTANTS & STORAGE
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////////////////
                                     CONFIG
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override { }

    /**
     * De-initialize the module with the given data
     *
     * @param data The data to de-initialize the module with
     */
    function onUninstall(bytes calldata data) external override { }

    /**
     * Check if the module is initialized
     * @param smartAccount The smart account to check
     *
     * @return true if the module is initialized, false otherwise
     */
    function isInitialized(address smartAccount) external view returns (bool) { }

    /*//////////////////////////////////////////////////////////////////////////
                                     MODULE LOGIC
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * Pre-checks an execution
     *
     * @param account The account address
     * @param msgSender The sender of the execution to the account
     * @param msgData The data of the execution
     *
     * @return hookData The data to be used in the post-check
     */
    function _preCheck(
        address account,
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    )
        internal
        override
        returns (bytes memory hookData)
    {
        hookData = abi.encode(true);
    }

    /**
     * Post-checks an execution
     *
     * @param account The account address
     * @param hookData The data from the pre-check
     */
    function _postCheck(address account, bytes calldata hookData) internal override {
        (bool success) = abi.decode(hookData, (bool));
        if (!success) {
            revert("HookTemplate: execution failed");
        }
    }

    /*//////////////////////////////////////////////////////////////////////////
                                     INTERNAL
    //////////////////////////////////////////////////////////////////////////*/

    /*//////////////////////////////////////////////////////////////////////////
                                     METADATA
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * The name of the module
     *
     * @return name The name of the module
     */
    function name() external pure returns (string memory) {
        return "HookTemplate";
    }

    /**
     * The version of the module
     *
     * @return version The version of the module
     */
    function version() external pure returns (string memory) {
        return "0.0.1";
    }

    /**
     * Check if the module is of a certain type
     *
     * @param typeID The type ID to check
     *
     * @return true if the module is of the given type, false otherwise
     */
    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_HOOK;
    }
}
