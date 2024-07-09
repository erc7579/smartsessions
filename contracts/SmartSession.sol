// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

import {
    ModeCode as ExecutionMode,
    ExecType,
    CallType,
    CALLTYPE_BATCH,
    CALLTYPE_SINGLE,
    EXECTYPE_DEFAULT
} from "erc7579/lib/ModeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IAccountExecute } from "modulekit/external/ERC4337.sol";
import { IUserOpPolicy, IActionPolicy } from "contracts/interfaces/IPolicy.sol";

import { PolicyLib } from "./lib/PolicyLib.sol";
import { SignerLib } from "./lib/SignerLib.sol";
import { ConfigLib } from "./lib/ConfigLib.sol";
import { EncodeLib } from "./lib/EncodeLib.sol";
import { ExecutionLib } from "erc7579/lib/ExecutionLib.sol";

import "./DataTypes.sol";
import { SmartSessionBase } from "./SmartSessionBase.sol";
import "forge-std/console2.sol";

/**
 * TODO:
 *     - Permissions hook (spending limits?)
 *     - Check Policies/Signers via Registry before enabling
 */

/**
 *
 * @title SmartSession
 * @author zeroknots.eth (rhinestone) & Filipp Makarov (biconomy)
 */
contract SmartSession is SmartSessionBase {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using PolicyLib for *;
    using SignerLib for *;
    using ConfigLib for *;
    using ExecutionLib for *;
    using EncodeLib for *;

    error InvalidEnableSignature(address account, bytes32 hash);
    error UnsupportedExecutionType();
    error UnsupportedSmartSessionMode(SmartSessionMode mode);
    error InvalidUserOpSender(address sender);

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData vd)
    {
        address account = userOp.sender;
        if (account != msg.sender) revert InvalidUserOpSender(account);
        (SmartSessionMode mode, SignerId signerId, bytes calldata packedSig) = userOp.signature.unpackMode();

        if (mode == SmartSessionMode.USE) {
            vd = _enforcePolicies({
                signerId: signerId,
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: packedSig.decodeUse(),
                account: account
            });
        } else if (mode == SmartSessionMode.ENABLE) {
            // TODO: implement enable with registry.
            // registry check will break 4337 so it would make sense to have this in a opt in mode
        } else if (mode == SmartSessionMode.UNSAFE_ENABLE) {
            bytes memory usePermissionSig =
                _enablePolicies({ signerId: signerId, packedSig: packedSig, account: account });
            vd = _enforcePolicies({
                signerId: signerId,
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: usePermissionSig,
                account: account
            });
        } else {
            revert UnsupportedSmartSessionMode(mode);
        }
    }

    /**
     * Implements the capability to enable session keys during a userOp validation.
     * The configuration of policies and signer are hashed and signed by the user, this function uses ERC1271
     * to validate the signature of the user
     */
    function _enablePolicies(
        SignerId signerId,
        bytes calldata packedSig,
        address account
    )
        internal
        returns (bytes memory permissionUseSig)
    {
        EnableSessions memory enableData;
        (enableData, permissionUseSig) = packedSig.decodeEnable();
        uint256 nonce = ++$signerNonce[signerId][account];
        bytes32 hash = signerId.digest(nonce, enableData);

        // require signature on account
        // this is critical as it is the only way to ensure that the user is aware of the policies and signer
        if (IERC1271(account).isValidSignature(hash, enableData.permissionEnableSig) != EIP1271_MAGIC_VALUE) {
            revert InvalidEnableSignature(account, hash);
        }

        // enable ISigner for this session
        _enableISigner(signerId, account, enableData.isigner, enableData.isignerInitData);

        // enable all policies for this session
        $userOpPolicies.enable({ signerId: signerId, sessionId: sessionId(toUserOpPolicyId(signerId)), policyDatas: enableData.userOpPolicies, smartAccount: account });
        $erc1271Policies.enable({ signerId: signerId, sessionId: sessionId(toErc1271PolicyId(signerId)), policyDatas: enableData.erc1271Policies, smartAccount: account });
        $actionPolicies.enable({ signerId: signerId, actionPolicyDatas: enableData.actions, smartAccount: account });
    }

    /**
     * Implements the capability enforce policies and check ISigner signature for a session
     */
    function _enforcePolicies(
        SignerId signerId,
        bytes32 userOpHash,
        PackedUserOperation calldata userOp,
        bytes memory decompressedSignature,
        address account
    )
        internal
        returns (ValidationData vd)
    {
        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                 Check SessionKey ISigner                   */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

        // this call reverts if the ISigner is not set or signature is invalid
        $isigners.requireValidISigner({
            userOpHash: userOpHash,
            account: account,
            signerId: signerId,
            signature: decompressedSignature
        });

        /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
        /*                    Check UserOp Policies                   */
        /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
        // check userOp policies. This reverts if policies are violated
        vd = $userOpPolicies.check({
            userOp: userOp,
            signer: signerId,
            callOnIPolicy: abi.encodeCall(IUserOpPolicy.checkUserOpPolicy, (sessionId(signerId), userOp)),
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
                revert UnsupportedExecutionType();
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
                revert UnsupportedExecutionType();
            }
        }
        // SmartSession does not support executeFromUserOp,
        // should this function selector be used in the userOp: revert
        else if (selector == IAccountExecute.executeUserOp.selector) {
            revert UnsupportedExecutionType();
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

    // TODO: implement ERC1271 checks
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
