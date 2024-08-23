// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";
import { ISessionValidator } from "../interfaces/ISessionValidator.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
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
    mapping(ConfigId configId => mapping(bytes32 contentHash => mapping(address account => bool enabled))) internal
        $enabledERC7739Content;
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal $sessionValidators;

    function _enableISessionValidator(
        PermissionId permissionId,
        address account,
        ISessionValidator sessionValidator,
        bytes memory signerConfig
    )
        internal
    {
        if (
            address(sessionValidator) == address(0)
                || !sessionValidator.supportsInterface(type(ISessionValidator).interfaceId)
        ) {
            revert InvalidISessionValidator(sessionValidator);
        }
        // TODO: add registry check
        SignerConf storage $conf = $sessionValidators[permissionId][account];
        $conf.sessionValidator = sessionValidator;
        $conf.config.store(signerConfig);
    }

    function enableUserOpPolicies(PermissionId permissionId, PolicyData[] memory userOpPolicies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $userOpPolicies.enable({
            policyType: PolicyType.USER_OP,
            permissionId: permissionId,
            configId: permissionId.toUserOpPolicyId().toConfigId(),
            policyDatas: userOpPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableUserOpPolicies(PermissionId permissionId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $userOpPolicies.disable({
            policyType: PolicyType.USER_OP,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });
    }

    function enableERC1271Policies(PermissionId permissionId, PolicyData[] memory erc1271Policies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            policyDatas: erc1271Policies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableERC1271Policies(PermissionId permissionId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $erc1271Policies.disable({
            policyType: PolicyType.ERC1271,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });
    }

    function enableActionPolicies(PermissionId permissionId, ActionData[] memory actionPolicies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: actionPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    function disableActionPolicies(PermissionId permissionId, ActionId actionId, address[] calldata policies) public {
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        $actionPolicies.actionPolicies[actionId].disable({
            policyType: PolicyType.ACTION,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });
    }

    function enableSessions(Session[] calldata sessions) public returns (PermissionId[] memory permissionIds) {
        uint256 length = sessions.length;
        if (length == 0) revert InvalidData();
        permissionIds = new PermissionId[](length);
        for (uint256 i; i < length; i++) {
            Session calldata session = sessions[i];
            PermissionId permissionId = session.toPermissionId();
            $enabledSessions.add({ account: msg.sender, value: PermissionId.unwrap(permissionId) });
            _enableISessionValidator({
                permissionId: permissionId,
                account: msg.sender,
                sessionValidator: session.sessionValidator,
                signerConfig: session.sessionValidatorInitData
            });

            $userOpPolicies.enable({
                policyType: PolicyType.USER_OP,
                permissionId: permissionId,
                configId: permissionId.toUserOpPolicyId().toConfigId(),
                policyDatas: session.userOpPolicies,
                smartAccount: msg.sender,
                useRegistry: true
            });

            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(),
                policyDatas: session.erc7739Policies.erc1271Policies,
                smartAccount: msg.sender,
                useRegistry: true
            });

            $actionPolicies.enable({
                permissionId: permissionId,
                actionPolicyDatas: session.actions,
                smartAccount: msg.sender,
                useRegistry: true
            });

            permissionIds[i] = permissionId;
            emit SessionCreated(permissionId, msg.sender);
        }
    }

    function removeSession(PermissionId permissionId) public {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);
        $userOpPolicies.policyList[permissionId].removeAll(msg.sender);
        $erc1271Policies.policyList[permissionId].removeAll(msg.sender);

        uint256 actionLength = $actionPolicies.enabledActionIds[permissionId].length(msg.sender);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap($actionPolicies.enabledActionIds[permissionId].get(msg.sender, i));
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(msg.sender);
        }

        $enabledSessions.remove({ account: msg.sender, value: PermissionId.unwrap(permissionId) });
        emit SessionRemoved(permissionId, msg.sender);
    }

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        // It's allowed to install smartsessions on a ERC7579 account without any params
        if (data.length == 0) return;

        Session[] calldata sessions;

        // equivalent of abi.decode(data,Session[])
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
        uint256 configIdsCnt = $enabledSessions.length({ account: msg.sender });

        for (uint256 i; i < configIdsCnt; i++) {
            PermissionId configId = PermissionId.wrap($enabledSessions.at({ account: msg.sender, index: i }));
            removeSession(configId);
        }
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        uint256 configIdsCnt = $enabledSessions.length({ account: smartAccount });
        return configIdsCnt > 0;
    }

    function isSessionEnabled(PermissionId permissionId, address account) external view returns (bool) {
        return $enabledSessions.contains(account, PermissionId.unwrap(permissionId));
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        if (typeID == ERC7579_MODULE_TYPE_VALIDATOR) return true;

        // if SmartSessions is to be used as a ERC1271/ERC7739 validator module, the account has to implement  function
        // supportsNestedTypedDataSign() public view virtual returns (bytes32 result)
        // this can be achieved by adding this function selector in your 7579 account as a fallback handler
        // YOU MUST NOT add any of the write functions via 7579 fallback selector
        if (typeID == ERC7579_MODULE_TYPE_FALLBACK) return true;
    }

    function getSessionDigest(
        PermissionId permissionId,
        address account,
        Session memory data,
        SmartSessionMode mode
    )
        public
        view
        returns (bytes32)
    {
        uint256 nonce = $signerNonce[permissionId][account];
        return data.sessionDigest({ account: account, mode: mode, nonce: nonce });
    }

    function getPermissionId(Session calldata session) public pure returns (PermissionId permissionId) {
        permissionId = session.toPermissionId();
    }

    function _isISessionValidatorSet(PermissionId permissionId, address account) internal view returns (bool) {
        return address($sessionValidators[permissionId][account].sessionValidator) != address(0);
    }

    function isPermissionEnabled(
        PermissionId permissionId,
        address account,
        PolicyData[] memory userOpPolicies,
        PolicyData[] memory erc1271Policies,
        ActionData[] memory actions
    )
        external
        view
        returns (bool isEnabled)
    {
        //if ISessionValidator is not set for permissionId, the permission has not been enabled yet
        if (!_isISessionValidatorSet(permissionId, account)) {
            return false;
        }
        bool uo = $userOpPolicies.areEnabled({
            permissionId: permissionId,
            configId: permissionId.toUserOpPolicyId().toConfigId(account),
            smartAccount: account,
            policyDatas: userOpPolicies
        });
        bool erc1271 = $erc1271Policies.areEnabled({
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(account),
            smartAccount: account,
            policyDatas: erc1271Policies
        });
        bool action = $actionPolicies.areEnabled({
            permissionId: permissionId,
            smartAccount: account,
            actionPolicyDatas: actions
        });
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
