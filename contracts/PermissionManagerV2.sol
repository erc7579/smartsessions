// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { ERC7579ValidatorBase, ERC7579ExecutorBase } from "modulekit/Modules.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";

import {
    ModeLib,
    ModeCode as ExecutionMode,
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    CALLTYPE_STATIC,
    CALLTYPE_DELEGATECALL,
    EXECTYPE_DEFAULT,
    EXECTYPE_TRY
} from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";
import { ValidationDataLib } from "contracts/lib/ValidationDataLib.sol";

import { IERC7579Account, Execution } from "erc7579/interfaces/IERC7579Account.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { IAccountExecute } from "modulekit/external/ERC4337.sol";
import { ISigner } from "contracts/interfaces/ISigner.sol";
import { IUserOpPolicy, IActionPolicy, I1271Policy } from "contracts/interfaces/IPolicy.sol";
import { IAccountConfig } from "contracts/interfaces/IAccountConfig.sol";
import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as Bytes32Vec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/lib/ArrayMap4337Lib.sol";

import { PolicyLib } from "./lib/PolicyLib.sol";
import { SignerLib } from "./lib/SignerLib.sol";
import { SignatureDecodeLib } from "./lib/SignatureDecodeLib.sol";
import { Execution, ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

import "forge-std/console2.sol";
import "./DataTypes.sol";
import { PermissionManagerBase } from "./PermissionManagerBase.sol";

/**
 * TODO:
 *     - Renounce policies and signers
 *         - disable trustedForwarder config for given SA !!!
 *     - Permissions hook (soending limits?)
 *     - Check Policies/Signers via Registry before enabling
 *     - In policies contracts, change signerId to id
 */
contract PermissionManager is PermissionManagerBase, ERC7579ValidatorBase, ERC7579ExecutorBase {
    using AddressVecLib for *;
    using PolicyLib for *;
    using SignerLib for *;
    using ExecutionLib for *;
    using SignatureDecodeLib for *;

    error ExecuteUserOpIsNotSupported();

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

        vd = _enforcePolicies(userOpHash, userOp, packedSig, account);
    }

    function _enforcePolicies(
        bytes32 userOpHash,
        PackedUserOperation calldata userOp,
        bytes calldata signature,
        address account
    )
        internal
        returns (ValidationData vd)
    {
        SignerId signerId;
        (signerId, signature) = signature.decodeUse();

        // this will revert if ISigner signature is invalid
        $isigners.requireValidISigner({
            userOpHash: userOpHash,
            account: account,
            signerId: signerId,
            signature: signature
        });

        // check userOp policies
        vd = $userOpPolicies.check({
            userOp: userOp,
            signer: signerId,
            callOnIPolicy: abi.encodeCall(IUserOpPolicy.checkUserOp, (signerId, userOp))
        });

        bytes4 selector = bytes4(userOp.callData[0:4]);
        // if the selector indicates that the userOp is an execution,
        // all action policies have to be checked
        if (selector == IERC7579Account.execute.selector) {
            ExecutionMode mode = ExecutionMode.wrap(bytes32(userOp.callData[4:36]));
            CallType callType;
            ExecType execType;

            // solhint-disable-next-line no-inline-assembly
            assembly {
                callType := mode
                execType := shl(8, mode)
            }
            if (ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)) revert();
            // DEFAULT EXEC & BATCH CALL
            if (callType == CALLTYPE_BATCH) {
                vd = $actionPolicies.checkBatch7579Exec({ userOp: userOp, signerId: signerId });
            } else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) = userOp.callData.decodeSingle();
                vd = $actionPolicies.checkSingle7579Exec({
                    userOp: userOp,
                    signerId: signerId,
                    target: target,
                    value: value,
                    callData: callData
                });
            } else {
                revert();
            }
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
                callOnIPolicy: abi.encodeCall(
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
