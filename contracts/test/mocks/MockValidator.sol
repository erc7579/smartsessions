// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {
    IValidator,
    VALIDATION_SUCCESS,
    VALIDATION_FAILED,
    MODULE_TYPE_VALIDATOR
} from "erc7579/interfaces/IERC7579Module.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { SignatureCheckerLib } from "solady/utils/SignatureCheckerLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

contract MockValidator is IValidator {
    bytes4 constant ERC1271_INVALID = 0xffffffff;
    mapping(address => address) public smartAccountOwners;

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        view
        returns (uint256 validation)
    {
        return ECDSA.recover(MessageHashUtils.toEthSignedMessageHash(userOpHash), userOp.signature)
            == smartAccountOwners[msg.sender] ? VALIDATION_SUCCESS : VALIDATION_FAILED;
    }

    function isValidSignatureWithSender(
        address,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        returns (bytes4)
    {
        address owner = smartAccountOwners[msg.sender];
        // MAYBE SHOULD PREPARE REPLAY RESISTANT HASH BY APPENDING MSG.SENDER
        // SEE:
        // https://github.com/bcnmy/scw-contracts/blob/3362262dab34fa0f57e2fbe0e57a4bdbd5318165/contracts/smart-account/modules/EcdsaOwnershipRegistryModule.sol#L122-L132
        // OR USE EIP-712
        return SignatureCheckerLib.isValidSignatureNowCalldata(owner, hash, signature)
            ? EIP1271_MAGIC_VALUE
            : ERC1271_INVALID;
    }

    function onInstall(bytes calldata data) external {
        smartAccountOwners[msg.sender] = address(bytes20(data));
    }

    function onUninstall(bytes calldata data) external {
        data;
        delete smartAccountOwners[msg.sender];
    }

    function isModuleType(uint256 moduleTypeId) external pure returns (bool) {
        return moduleTypeId == MODULE_TYPE_VALIDATOR;
    }

    function isOwner(address account, address owner) external view returns (bool) {
        return smartAccountOwners[account] == owner;
    }

    function isInitialized(address) external pure returns (bool) {
        return false;
    }

    function getOwner(address account) external view returns (address) {
        return smartAccountOwners[account];
    }
}
