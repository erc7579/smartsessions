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
import { ExecutionLib as ExecutionLib } from "./lib/ExecutionLib.sol";

import { IERC7579Account } from "erc7579/interfaces/IERC7579Account.sol";
import { IAccountExecute } from "modulekit/external/ERC4337.sol";
import { IUserOpPolicy, IActionPolicy } from "contracts/interfaces/IPolicy.sol";

import { PolicyLib } from "./lib/PolicyLib.sol";
import { SignerLib } from "./lib/SignerLib.sol";
import { ConfigLib } from "./lib/ConfigLib.sol";
import { EncodeLib } from "./lib/EncodeLib.sol";

import "./DataTypes.sol";
import { SmartSessionBase } from "./SmartSessionBase.sol";
import { IdLib } from "./lib/IdLib.sol";

import "forge-std/console2.sol";

/**
 * TODO:
 *     ✅ The flow where permission doesn't enable the new signer, just adds policies for the existing one
 *     - ISigner => Stateless Sig Validator (discussed with zeroknots
 *               https://biconomyworkspace.slack.com/archives/D063X01CUEA/p1720520086702069)
 *     - MultiChain Permission Enable Data (chainId is in EncodeLib.digest now)
 *     ✅ 'No Signature verification required' flow
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
    using IdLib for *;
    using PolicyLib for *;
    using SignerLib for *;
    using ConfigLib for *;
    using ExecutionLib for *;
    using EncodeLib for *;

    error InvalidEnableSignature(address account, bytes32 hash);
    error InvalidSignerId();
    error UnsupportedExecutionType();
    error UnsupportedSmartSessionMode(SmartSessionMode mode);
    error InvalidUserOpSender(address sender);
    error PermissionPartlyEnabled();

    /**
     * ERC4337/ERC7579 validation function
     * the primiary purpose of this function, is to validate if a userOp forwarded by a 7579 account is valid.
     * This function will disect the userop.singature field, and parse out the provided SignerId, which identifies a
     * unique ID of a dapp for a specific user. n Policies and one Signer contract are mapped to this Id and will be
     * checked. Only UserOps that pass policies and signer checks, are considered valid.
     * Enable Flow:
     *     SmartSessions allows session keys to be created within the "first" UserOp. If the enable flow is chosen, the
     *     EnableSessions data, which is packed in userOp.signature is parsed, and stored in the SmartSession storage.
     *
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        override
        returns (ValidationData vd)
    {
        // ensure that userOp.sender == account
        // SmartSession will sstore configs for a certain account,
        // so we have to ensure that unauthorized access is not possible
        address account = userOp.sender;
        if (account != msg.sender) revert InvalidUserOpSender(account);

        // unpacking data packed in userOp.signature
        (SmartSessionMode mode, SignerId signerId, bytes calldata packedSig) = userOp.signature.unpackMode();

        // If the SmartSession.USE mode was selected, no futher policies have to be enabled.
        // We can go straight to userOp validation
        // This condition is the average case, so should be handled as the first condition
        if (mode == SmartSessionMode.USE) {
            vd = _enforcePolicies({
                signerId: signerId,
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: packedSig.decodeUse(),
                account: account
            });
        }
        // If the SmartSession.ENABLE mode was selected, the userOp.signature will contain the EnableSessions data
        // This data will be used to enable policies and signer for the session
        // The signature of the user on the EnableSessions data will be checked
        // If the signature is valid, the policies and signer will be enabled
        // after enabling the session, the policies will be enforced on the userOp similarly to the SmartSession.USE
        else if (mode == SmartSessionMode.ENABLE || mode == SmartSessionMode.UNSAFE_ENABLE) {
            // _enablePolicies slices out the data required to enable a session from userOp.signature and returns the
            // data required to use the actual session
            bytes memory usePermissionSig =
                _enablePolicies({ signerId: signerId, packedSig: packedSig, account: account, mode: mode });

            vd = _enforcePolicies({
                signerId: signerId,
                userOpHash: userOpHash,
                userOp: userOp,
                decompressedSignature: usePermissionSig,
                account: account
            });
        }
        // if an Unknown mode is provided, the function will revert
        else {
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
        address account,
        SmartSessionMode mode
    )
        internal
        returns (bytes memory permissionUseSig)
    {
        EnableSessions memory enableData;
        (enableData, permissionUseSig) = packedSig.decodeEnable();

        // in order to prevent replay of an enable flow, we have to iterate a nonce.
        uint256 nonce = $signerNonce[enableData.isigner][account]++;

        // derive EIP712 of the EnableSessions data. The account owner is expected to sign this via ERC1271
        bytes32 hash = enableData.isigner.digest(nonce, enableData, mode);
        // ensure that the signerId, that was provided, is the correct getSignerId
        if (signerId != getSignerId(enableData.isigner, enableData.isignerInitData)) {
            revert InvalidSignerId();
        }

        // require signature on account
        // this is critical as it is the only way to ensure that the user is aware of the policies and signer
        // NOTE: although SmartSession implements a ERC1271 feature, it CAN NOT be used as a valid ERC1271 validator for
        // this step.
        if (IERC1271(account).isValidSignature(hash, enableData.permissionEnableSig) != EIP1271_MAGIC_VALUE) {
            revert InvalidEnableSignature(account, hash);
        }

        // enable ISigner for this session
        // if it has already been enabled and the enableData.isigner is address(0), that means
        // this enableData is to add policies, not to enable a new signer => skip this step
        // !!! the flow above is now broken as signerId depends on isigner address, so if address(0)
        // is passed, it won't generate same signerId, so we can't user address(0) as isigner
        // to skip enabling new isigner
        if (!_isISignerSet(signerId, account) && address(enableData.isigner) != address(0)) {
            _enableISigner(signerId, account, enableData.isigner, enableData.isignerInitData);
        }

        // if SmartSessionMode.ENABLE is used, the Registry has to be queried to ensure that Policies and Signers are
        // considered safe
        bool useRegistry = mode != SmartSessionMode.UNSAFE_ENABLE;

        // enable all policies for this session
        $userOpPolicies.enable({
            signerId: signerId,
            sessionId: signerId.toUserOpPolicyId().toSessionId(),
            policyDatas: enableData.userOpPolicies,
            smartAccount: account,
            useRegistry: useRegistry
        });
        $erc1271Policies.enable({
            signerId: signerId,
            sessionId: signerId.toErc1271PolicyId().toSessionId(),
            policyDatas: enableData.erc1271Policies,
            smartAccount: account,
            useRegistry: useRegistry
        });
        $actionPolicies.enable({
            signerId: signerId,
            actionPolicyDatas: enableData.actions,
            smartAccount: account,
            useRegistry: useRegistry
        });
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
            callOnIPolicy: abi.encodeCall(IUserOpPolicy.checkUserOpPolicy, (signerId.toSessionId(), userOp)),
            minPoliciesToEnforce: 0
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
                (address target, uint256 value, bytes calldata callData) =
                    userOp.callData.decodeUserOpCallData().decodeSingle();
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
            ActionId actionId = account.toActionId(userOp.callData);

            vd = $actionPolicies.actionPolicies[actionId].check({
                userOp: userOp,
                signer: signerId,
                callOnIPolicy: abi.encodeCall(
                    IActionPolicy.checkAction,
                    (
                        signerId.toSessionId(actionId),
                        account, // target
                        0, // value
                        userOp.callData, // data
                        userOp
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

    function isPermissionEnabled(
        SignerId signerId,
        address account,
        PolicyData[] memory userOpPolicies,
        PolicyData[] memory erc1271Policies,
        ActionData[] memory actions
    )
        external
        view
        returns (bool isEnabled)
    {   
        //if ISigner is not set for signerId, the permission has not been enabled yet
        if (!_isISignerSet(signerId, account)) {
            return false;
        }
        bool uo = $userOpPolicies.areEnabled({
            signerId: signerId,
            sessionId: signerId.toUserOpPolicyId().toSessionId(account),
            smartAccount: account,
            policyDatas: userOpPolicies
        });
        bool erc1271 = $erc1271Policies.areEnabled({
            signerId: signerId,
            sessionId: signerId.toErc1271PolicyId().toSessionId(account),
            smartAccount: account,
            policyDatas: erc1271Policies
        });
        bool action =
            $actionPolicies.areEnabled({ signerId: signerId, smartAccount: account, actionPolicyDatas: actions });
        uint256 res;
        assembly {
            res := add(add(uo, erc1271), action)
        }
        if (res == 0) return false;
        else if (res == 3) return true;
        else revert PermissionPartlyEnabled();
        // partly enabled permission will prevent the full permission to be enabled
        // and we can not consider it being fully enabled, as it missed some policies we'd want to enforce
        // as per given 'enableData'
    }
}
