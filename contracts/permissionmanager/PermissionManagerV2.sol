// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import {
    ModeLib,
    ExecutionMode,
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    CALLTYPE_STATIC,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY
} from "contracts/utils/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";
import { PermissionDescriptor, PermissionDescriptorLib } from "contracts/utils/lib/PermissionDescriptorLib.sol";
import { NonceMixinLib } from "contracts/utils/lib/NonceMixinLib.sol";

import {
    IPermissionManager,
    NO_SIGNATURE_VALIDATION_REQUIRED
} from "contracts/interfaces/validators/IPermissionManager.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute } from "modulekit/external/ERC4337.sol";
import { ISignerValidator as ISigner } from "contracts/interfaces/ISignerValidator.sol";
import { ITrustedForwarder } from "contracts/utils/interfaces/ITrustedForwarder.sol";
import { IUserOpPolicy, IActionPolicy, I1271Policy } from "contracts/interfaces/IPolicies.sol";
import { IAccountConfig } from "contracts/utils/interfaces/IAccountConfig.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/utils/lib/ArrayMap4337Lib.sol";

import "forge-std/console2.sol";
import "./DataTypes.sol";

/**
 * TODO:
 *     - Renounce policies and signers
 *         - disable trustedForwarder config for given SA !!!
 *     - Permissions hook (soending limits?)
 *     - Check Policies/Signers via Registry before enabling
 *     - In policies contracts, change signerId to id
 */
contract PermissionManager is ERC7579ValidatorBase, ERC7579ExecutorBase, IPermissionManager {
    using AddressVecLib for *;

    mapping(SignerId => AddressVec) internal $userOpPolicies;
    mapping(SignerId => AddressVec) internal $actionPolicies;
    mapping(SignerId => AddressVec) internal $erc1271Policies;
    mapping(SignerId => BytesVec) internal $enabledSignerIds;
    mapping(SignerId => BytesVec) internal $enabledActionIds;

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData vd)
    {
        bytes4 selector = bytes4(userOp.callData[0:4]);

        if (selector == IAccountExecute.executeUserOp.selector) {
            revert ExecuteUserOpIsNotSupported();
        }

        Mode mode = Mode(uint8(bytes1(userOp.signature[:1])));

        if (mode == Mode.ENABLE) {
            // TODO: implement enable
        }

        // TODO: slice out from userOp.signature
        SignerId signerId;
        bytes calldata signature;
        ISigner isigner;

        if (isigner.checkSignature(signerId, userOpHash, signature) != EIP1271_SUCCESS) revert();

        vd = $userOpPolicies.check({
            userOp: userOp,
            signer: signerId,
            callData: abi.encodeCall(IUserOpPolicy.checkUserOp, (signer, userOp))
        });

        if (selector == IERC7579Account.execute.selector) {
            // vd = $actionPolicies.checkExecution({
            //     userOp: userOp,
            //     signer: signerId,
            //     callData: abi.encodeCall(IActionPolicy.checkAction, (signer, userOp))
            // });

            // TODO: parse out the execution targets
        } else {
            vd = $actionPolicies.check({
                userOp: userOp,
                signer: signerId,
                callData: abi.encodeCall(IActionPolicy.checkAction, (id, userOp.sender, 0, userOp.callData, userOp))
            });
        }
    }

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        virtual
        override
        returns (bytes4 sigValidationResult)
    { }

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

    function isInitialized(address smartAccount) external view returns (bool) { }
}
