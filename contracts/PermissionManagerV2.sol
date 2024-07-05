// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

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
import { ConfigLib } from "./lib/ConfigLib.sol";
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

/**
 *
 * @title PermissionManager
 * @author Filipp Makarov (biconomy) & zeroknots.eth (rhinestone)
 */
contract PermissionManager is PermissionManagerBase {
    using AddressVecLib for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using PolicyLib for *;
    using SignerLib for *;
    using ConfigLib for *;
    using ExecutionLib for *;
    using SignatureDecodeLib for *;

    error InvalidEnableSignature(address account, bytes32 hash);
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
        if (account != msg.sender) revert();
        (PermissionManagerMode mode, bytes calldata packedSig) = userOp.decodeMode();

        if (mode == PermissionManagerMode.ENABLE) {
            // TODO: implement enable with registry.
            // registry check will break 4337 so it would make sense to have this in a opt in mode
        } else if (mode == PermissionManagerMode.UNSAFE_ENABLE) {
            packedSig = _enablePolicies(packedSig, account);
        }

        vd = _enforcePolicies(userOpHash, userOp, packedSig, account);
    }

    function _enablePolicies(
        bytes calldata packedSig,
        address account
    )
        internal
        returns (bytes calldata permissionUseSig)
    {
        EnableSessions memory enableData;
        SignerId signerId;
        (enableData, signerId, permissionUseSig) = packedSig.decodePackedSigEnable();
        bytes32 hash = signerId.digest(enableData); // TODO add signerId to hash
        // require signature on account

        if (IERC1271(account).isValidSignature(hash, enableData.permissionEnableSig) != EIP1271_MAGIC_VALUE) {
            revert InvalidEnableSignature(account, hash);
        }

        $userOpPolicies.enable({ signerId: signerId, policyDatas: enableData.userOpPolicies, smartAccount: account });
        $erc1271Policies.enable({ signerId: signerId, policyDatas: enableData.erc1271Policies, smartAccount: account });
        $actionPolicies.enable({ signerId: signerId, actionPolicyDatas: enableData.actions, smartAccount: account });
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

        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                 Check SessionKey ISigner                   */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        $isigners.requireValidISigner({
            userOpHash: userOpHash,
            account: account,
            signerId: signerId,
            signature: signature
        });

        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                    Check UserOp Policies                   */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        vd = $userOpPolicies.check({
            userOp: userOp,
            signer: signerId,
            callOnIPolicy: abi.encodeCall(IUserOpPolicy.checkUserOp, (sessionId(signerId), userOp)),
            minPoliciesToEnforce: 1
        });

        bytes4 selector = bytes4(userOp.callData[0:4]);

        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                      Handle Executions                     */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        // if the selector indicates that the userOp is an execution,
        // action policies have to be checked
        if (selector == IERC7579Account.execute.selector) {
            ExecutionMode mode = ExecutionMode.wrap(bytes32(userOp.callData[4:36]));
            CallType callType;
            ExecType execType;

            // solhint-disable-next-line no-inline-assembly
            assembly {
                callType := mode
                execType := shl(8, mode)
            }
            if (ExecType.unwrap(execType) != ExecType.unwrap(EXECTYPE_DEFAULT)) {
                revert();
            }
            // DEFAULT EXEC & BATCH CALL
            else if (callType == CALLTYPE_BATCH) {
                vd = $actionPolicies.actionPolicies.checkBatch7579Exec({ userOp: userOp, signerId: signerId });
            }
            // DEFAULT EXEC & SINGLE CALL
            else if (callType == CALLTYPE_SINGLE) {
                (address target, uint256 value, bytes calldata callData) = userOp.callData.decodeSingle();
                vd = $actionPolicies.actionPolicies.checkSingle7579Exec({
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
        // PermisisonManager does not support executeFromUserOp,
        // should this function selector be used in the userOp: revert
        else if (selector == IAccountExecute.executeUserOp.selector) {
            revert ExecuteUserOpIsNotSupported();
        }
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                        Handle Actions                      */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        // all other executions are supported and are handled by the actionPolicies
        else {
            ActionId actionId = toActionId(userOp.sender, userOp.callData);
            vd = $actionPolicies.actionPolicies[actionId].check({
                userOp: userOp,
                signer: signerId,
                callOnIPolicy: abi.encodeCall(
                    IActionPolicy.checkAction,
                    (
                        sessionId({ signerId: signerId, actionId: actionId }), // actionId
                        userOp.sender, // TODO: check if this is correct
                        userOp.sender, // target
                        0, // value
                        userOp.callData // data
                    )
                ),
                minPoliciesToEnforce: 0
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
}
