// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

import "./utils/EnumerableSet4337.sol";
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
import { HashLib } from "./lib/HashLib.sol";
import { SmartSessionBase } from "./SmartSessionBase.sol";
import { SmartSessionERC7739 } from "./SmartSessionERC7739.sol";
import { IdLib } from "./lib/IdLib.sol";
import { SmartSessionModeLib } from "./lib/SmartSessionModeLib.sol";

import "forge-std/console2.sol";

/**
 * TODO:
*      - 7739
*      - rename SignerId ?
 *     - Permissions hook (spending limits?)
 */

/**
 *
 * @title SmartSession
 * @author zeroknots.eth (rhinestone) & Filipp Makarov (biconomy)
 */
contract SmartSession is SmartSessionBase, SmartSessionERC7739 {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using IdLib for *;
    using HashLib for *;
    using PolicyLib for *;
    using SignerLib for *;
    using ConfigLib for *;
    using ExecutionLib for *;
    using EncodeLib for *;
    using SmartSessionModeLib for SmartSessionMode;

    error InvalidEnableSignature(address account, bytes32 hash);
    error InvalidSignerId(SignerId signerId);
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
        if (mode.isUseMode()) {
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
        else if (mode.isEnableMode()) {
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
        uint256 nonce = $signerNonce[signerId][account]++;
        bytes32 hash =  enableData.getAndVerifyDigest(nonce, mode);

        // ensure that the signerId, that was provided, is the correct getSignerId
        if (signerId != getSignerId(enableData.sessionToEnable)) {
            revert InvalidSignerId(signerId);
        }

        // require signature on account
        // this is critical as it is the only way to ensure that the user is aware of the policies and signer
        // NOTE: although SmartSession implements a ERC1271 feature, it CAN NOT be used as a valid ERC1271 validator for
        // this step.
        if (IERC1271(account).isValidSignature(hash, enableData.permissionEnableSig) != EIP1271_MAGIC_VALUE) {
            revert InvalidEnableSignature(account, hash);
        }

        // enable ISigner for this session
        // if we do not have to enable ISigner, we just add policies
        // Attention: policies to add should be all new.
        if (!_isISignerSet(signerId, account) && mode.enableSigner()) {
            _enableISigner(signerId, account, enableData.sessionToEnable.isigner, enableData.sessionToEnable.isignerInitData);
        } 

        // if SmartSessionMode.ENABLE is used, the Registry has to be queried to ensure that Policies and Signers are
        // considered safe
        bool useRegistry = mode.useRegistry();

        // enable all policies for this session
        $userOpPolicies.enable({
            signerId: signerId,
            sessionId: signerId.toUserOpPolicyId().toSessionId(),
            policyDatas: enableData.sessionToEnable.userOpPolicies,
            smartAccount: account,
            useRegistry: useRegistry
        });
        $erc1271Policies.enable({
            signerId: signerId,
            sessionId: signerId.toErc1271PolicyId().toSessionId(),
            policyDatas: enableData.sessionToEnable.erc7739Policies.erc1271Policies,
            smartAccount: account,
            useRegistry: useRegistry
        });
        $actionPolicies.enable({
            signerId: signerId,
            actionPolicyDatas: enableData.sessionToEnable.actions,
            smartAccount: account,
            useRegistry: useRegistry
        });

        $enabledSessions.add(msg.sender, SignerId.unwrap(signerId));
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
        // ensure that the signerId is enabled
        if (!$enabledSessions.contains({ account: account, value: SignerId.unwrap(signerId) })) {
            revert InvalidSignerId(signerId);
        }
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

    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    )
        external
        view
        override
        returns (bytes4 result)
    {
        // disallow that session can be authorized by other sessions
        if (sender == address(this)) return 0xffffffff;

        bool success = _erc1271IsValidSignatureViaNestedEIP712(sender, hash, _erc1271UnwrapSignature(signature));
        /// @solidity memory-safe-assembly
        assembly {
            // `success ? bytes4(keccak256("isValidSignature(bytes32,bytes)")) : 0xffffffff`.
            // We use `0xffffffff` for invalid, in convention with the reference implementation.
            result := shl(224, or(0x1626ba7e, sub(0, iszero(success))))
        }
    }

    function _erc1271IsValidSignatureNowCalldata(
        address sender,
        bytes32 hash,
        bytes calldata signature,
        bytes calldata contents
    )
        internal
        view
        virtual
        override
        returns (bool valid)
    {
        console2.log(string(contents));
        bytes32 contentHash = string(contents).hashERC7739Content();
        SignerId signerId = SignerId.wrap(bytes32(signature[0:32]));
        signature = signature[32:];
        SessionId sessionId = signerId.toErc1271PolicyId().toSessionId(msg.sender);
        if (!$enabledERC7739Content[sessionId][contentHash][msg.sender]) return false;
        valid = $erc1271Policies.checkERC1271({
            account: msg.sender,
            requestSender: sender,
            hash: hash,
            signature: signature,
            signerId: signerId,
            sessionId: sessionId,
            minPoliciesToEnforce: 0
        });

        if (!valid) return false;
        // this call reverts if the ISigner is not set or signature is invalid
        return $isigners.isValidISigner({ hash: hash, account: msg.sender, signerId: signerId, signature: signature });
    }

    function _domainNameAndVersion() internal pure override returns (string memory, string memory) {
        return ("SmartSession", "1");
    }
}
