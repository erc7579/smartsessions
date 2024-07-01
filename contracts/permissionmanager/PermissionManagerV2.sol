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
import { NonceMixinLib } from "contracts/utils/lib/NonceMixinLib.sol";

import {
    IPermissionManager,
    NO_SIGNATURE_VALIDATION_REQUIRED
} from "contracts/interfaces/validators/IPermissionManager.sol";
import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute } from "modulekit/external/ERC4337.sol";
import { ISigner } from "contracts/permissionmanager/interfaces/ISigner.sol";
import { IUserOpPolicy, IActionPolicy, I1271Policy } from "contracts/permissionmanager/interfaces/IPolicy.sol";
import { IAccountConfig } from "contracts/utils/interfaces/IAccountConfig.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/utils/lib/ArrayMap4337Lib.sol";

import { PolicyLib } from "./lib/PolicyLib.sol";
import { SignatureDecodeLib } from "./lib/SignatureDecodeLib.sol";

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
    using PolicyLib for *;
    using SignatureDecodeLib for *;

    mapping(SignerId => AddressVec) internal $userOpPolicies;
    mapping(ActionId => mapping(SignerId => AddressVec)) internal $actionPolicies;
    mapping(SignerId => AddressVec) internal $erc1271Policies;
    mapping(SignerId => BytesVec) internal $enabledSignerIds;
    mapping(SignerId => BytesVec) internal $enabledActionIds;
    mapping(SignerId => mapping(address smartAccount => ISigner)) internal $isigners;

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData vd)
    {
        address account = userOp.sender;
        (PermissionManagerMode mode, bytes calldata packedSig) = userOp.decodeMode();

        if (mode == PermissionManagerMode.ENABLE) {
            // TODO: implement enable
        } else if (mode == PermissionManagerMode.UNSAFE_ENABLE) { }

        // TODO: slice out from userOp.signature
        (SignerId signerId, bytes calldata signature) = packedSig.decodeUse();
        ISigner isigner = $isigners[signerId][account];

        // check signature of ISigner first.
        // policies only need to be processed if the signature is correct
        if (
            isigner.checkSignature({ signerId: signerId, sender: userOp.sender, hash: userOpHash, sig: signature })
                != EIP1271_SUCCESS
        ) revert();

        // check userOp policies
        vd = $userOpPolicies.check({
            userOp: userOp,
            signer: signerId,
            callData: abi.encodeCall(IUserOpPolicy.checkUserOp, (signerId, userOp))
        });

        bytes4 selector = bytes4(userOp.callData[0:4]);
        // if the selector indicates that the userOp is an execution,
        // all action policies have to be checked
        if (selector == IERC7579Account.execute.selector) {
            vd = $actionPolicies.checkExecution({ userOp: userOp, signerId: signerId });
        }
        // PermisisonManager does not support executeFromUserOp, should this function selector be used in the userOp,
        // revert
        else if (selector == IAccountExecute.executeUserOp.selector) {
            revert ExecuteUserOpIsNotSupported();
        }
        // all other executions are supported and are handled by the actionPolicies
        else {
            ActionId actionId = userOp.sender.toActionId(userOp.callData);
            vd = $actionPolicies[actionId].check({
                userOp: userOp,
                signer: signerId,
                callData: abi.encodeCall(
                    IActionPolicy.checkAction,
                    (
                        toActionPolicyId({ signerId: signerId, actionId: actionId }), // actionId
                        userOp.sender, // target
                        0, // value
                        userOp.callData, // data
                        userOp // userOp
                    )
                )
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

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        return typeID == TYPE_VALIDATOR || typeID == TYPE_EXECUTOR;
    }
}
