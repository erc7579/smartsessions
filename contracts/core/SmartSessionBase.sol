// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";
import { ISigner } from "../interfaces/ISigner.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";
import { ConfigLib } from "../lib/ConfigLib.sol";
import { EncodeLib } from "../lib/EncodeLib.sol";
import { PolicyLib } from "../lib/PolicyLib.sol";
import { IdLib } from "../lib/IdLib.sol";
import { HashLib } from "../lib/HashLib.sol";
import { NonceManager } from "./NonceManager.sol";

abstract contract SmartSessionBase is ISmartSession, NonceManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;
    using FlatBytesLib for *;
    using HashLib for Session;
    using PolicyLib for *;
    using ConfigLib for *;
    using EncodeLib for *;
    using IdLib for *;
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using AssociatedArrayLib for *;
    using ConfigLib for Policy;
    using ConfigLib for EnumerableActionPolicy;

    Policy internal $userOpPolicies;
    Policy internal $erc1271Policies;
    EnumerableActionPolicy internal $actionPolicies;
    EnumerableSet.Bytes32Set internal $enabledSessions;
    mapping(SessionId => mapping(bytes32 contentHash => mapping(address account => bool enabled))) internal
        $enabledERC7739Content;
    mapping(SignerId signerId => mapping(address smartAccount => SignerConf)) internal $isigners;

    function _enableISigner(SignerId signerId, address account, ISigner isigner, bytes memory signerConfig) internal {
        if (!isigner.supportsInterface(type(ISigner).interfaceId)) {
            revert InvalidISigner(isigner);
        }
        // TODO: add registry check
        SignerConf storage $conf = $isigners[signerId][account];
        $conf.isigner = isigner;
        $conf.config.store(signerConfig);
    }

    function enableUserOpPolicies(SignerId signerId, PolicyData[] memory userOpPolicies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $userOpPolicies.enable({
            policyType: PolicyType.USER_OP,
            signerId: signerId,
            sessionId: signerId.toUserOpPolicyId().toSessionId(),
            policyDatas: userOpPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableUserOpPolicies(SignerId signerId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $userOpPolicies.disable({
            policyType: PolicyType.USER_OP,
            smartAccount: msg.sender,
            signerId: signerId,
            policies: policies
        });
    }

    function enableERC1271Policies(SignerId signerId, PolicyData[] memory erc1271Policies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            signerId: signerId,
            sessionId: signerId.toErc1271PolicyId().toSessionId(),
            policyDatas: erc1271Policies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableERC1271Policies(SignerId signerId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $erc1271Policies.disable({
            policyType: PolicyType.ERC1271,
            smartAccount: msg.sender,
            signerId: signerId,
            policies: policies
        });
    }

    function enableActionPolicies(SignerId signerId, ActionData[] memory actionPolicies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $actionPolicies.enable({
            signerId: signerId,
            actionPolicyDatas: actionPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableActionPolicies(SignerId signerId, ActionId actionId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, SignerId.unwrap(signerId)) == false) revert InvalidSession(signerId);
        $actionPolicies.actionPolicies[actionId].disable({
            policyType: PolicyType.ACTION,
            smartAccount: msg.sender,
            signerId: signerId,
            policies: policies
        });
    }

    function enableSessions(Session[] calldata sessions) public returns (SignerId[] memory signerIds) {
        uint256 length = sessions.length;
        signerIds = new SignerId[](length);
        for (uint256 i; i < length; i++) {
            Session calldata session = sessions[i];
            SignerId signerId = getSignerId(session);
            $enabledSessions.add({ account: msg.sender, value: SignerId.unwrap(signerId) });
            _enableISigner({
                signerId: signerId,
                account: msg.sender,
                isigner: session.isigner,
                signerConfig: session.isignerInitData
            });

            $userOpPolicies.enable({
                policyType: PolicyType.USER_OP,
                signerId: signerId,
                sessionId: signerId.toUserOpPolicyId().toSessionId(),
                policyDatas: session.userOpPolicies,
                smartAccount: msg.sender,
                useRegistry: true
            });

            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                signerId: signerId,
                sessionId: signerId.toErc1271PolicyId().toSessionId(),
                policyDatas: session.erc7739Policies.erc1271Policies,
                smartAccount: msg.sender,
                useRegistry: true
            });

            $actionPolicies.enable({
                signerId: signerId,
                actionPolicyDatas: session.actions,
                smartAccount: msg.sender,
                useRegistry: true
            });

            $enabledSessions.add(msg.sender, SignerId.unwrap(signerId));
            console2.logBytes32(SignerId.unwrap(signerId));
            signerIds[i] = signerId;
            emit SessionCreated(signerId, msg.sender);
        }
    }

    function removeSession(SignerId signerId) public {
        $userOpPolicies.policyList[signerId].removeAll(msg.sender);
        $erc1271Policies.policyList[signerId].removeAll(msg.sender);

        uint256 actionLength = $actionPolicies.enabledActionIds[signerId].length(msg.sender);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap($actionPolicies.enabledActionIds[signerId].get(msg.sender, i));
            $actionPolicies.actionPolicies[actionId].policyList[signerId].removeAll(msg.sender);
        }

        $enabledSessions.remove({ account: msg.sender, value: SignerId.unwrap(signerId) });
        emit SessionRemoved(signerId, msg.sender);
    }

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) return;

        Session[] calldata sessions;
        assembly ("memory-safe") {
            let dataPointer := add(data.offset, calldataload(data.offset))

            sessions.offset := add(dataPointer, 32)
            sessions.length := calldataload(dataPointer)
        }
        enableSessions(sessions);
    }

    /**
     * De-initialize the module with the given data
     */
    function onUninstall(bytes calldata /*data*/ ) external override {
        uint256 sessionIdsCnt = $enabledSessions.length({ account: msg.sender });

        for (uint256 i; i < sessionIdsCnt; i++) {
            SignerId sessionId = SignerId.wrap($enabledSessions.at({ account: msg.sender, index: i }));
            removeSession(sessionId);
        }
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        uint256 sessionIdsCnt = $enabledSessions.length({ account: smartAccount });
        return sessionIdsCnt > 0;
    }

    function isSessionEnabled(SignerId signerId, address account) external view returns (bool) {
        return $enabledSessions.contains(account, SignerId.unwrap(signerId));
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        if (typeID == ERC7579_MODULE_TYPE_VALIDATOR) return true;
        if (typeID == ERC7579_MODULE_TYPE_FALLBACK) return true;
    }

    function getDigest(
        SignerId signerId,
        address account,
        Session memory data,
        SmartSessionMode mode
    )
        public
        view
        returns (bytes32)
    {
        uint256 nonce = $signerNonce[signerId][account];
        return data.digest({ mode: mode, nonce: nonce });
    }

    function getSignerId(Session memory session) public pure returns (SignerId signerId) {
        signerId = SignerId.wrap(keccak256(abi.encode(session.isigner, session.isignerInitData, session.salt)));
    }

    function _isISignerSet(SignerId signerId, address account) internal view returns (bool) {
        return address($isigners[signerId][account].isigner) != address(0);
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
}
