// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";
import { ConfigLib } from "../lib/ConfigLib.sol";
import { EncodeLib } from "../lib/EncodeLib.sol";
import { PolicyLib } from "../lib/PolicyLib.sol";
import { IdLib } from "../lib/IdLib.sol";
import { HashLib } from "../lib/HashLib.sol";
import { NonceManager } from "./NonceManager.sol";

abstract contract SmartSessionBase is ISmartSession, NonceManager {
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using EnumerableSet for EnumerableSet.AddressSet;
    using HashLib for Session;
    using PolicyLib for *;
    using ConfigLib for *;
    using EncodeLib for *;
    using IdLib for *;
    using ConfigLib for Policy;
    using ConfigLib for EnumerableActionPolicy;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                    SmartSession Storage                    */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    /**
     * In order to comply with ERC-4337 storage restrictions, every storage in smart session is using associated
     * storage.
     */
    Policy internal $userOpPolicies;
    Policy internal $erc1271Policies;
    EnumerableActionPolicy internal $actionPolicies;
    EnumerableSet.Bytes32Set internal $enabledSessions;
    mapping(PermissionId permissionId => EnumerableSet.Bytes32Set enabledContentHashes) internal $enabledERC7739Content;
    mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) internal $sessionValidators;

    /**
     * @notice Enable user operation policies for a specific permission
     * @dev This function allows adding or updating user operation policies
     * @param permissionId The unique identifier for the permission
     * @param userOpPolicies An array of PolicyData structures containing policy information
     */
    function enableUserOpPolicies(PermissionId permissionId, PolicyData[] memory userOpPolicies) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        // Enable the specified user operation policies
        $userOpPolicies.enable({
            policyType: PolicyType.USER_OP,
            permissionId: permissionId,
            configId: permissionId.toUserOpPolicyId().toConfigId(),
            policyDatas: userOpPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    /**
     * @notice Disable specific user operation policies for a given permission
     * @param permissionId The unique identifier for the permission
     * @param policies An array of policy addresses to be disabled
     */
    function disableUserOpPolicies(PermissionId permissionId, address[] calldata policies) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        // Disable the specified user operation policies
        $userOpPolicies.disable({
            policyType: PolicyType.USER_OP,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });
    }

    /**
     * @notice Disable all user operation policies for a given permission
     * @param permissionId The unique identifier for the permission
     */
    function disableUserOpPolicies(PermissionId permissionId) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }
        // Disable all user operation policies
        $userOpPolicies.disableAll({
            policyType: PolicyType.USER_OP,
            smartAccount: msg.sender,
            permissionId: permissionId
        });
    }
    
    /**
     * @notice Enable ERC1271 policies for a specific permission
     * @param permissionId The unique identifier for the permission
     * @param erc1271Policies An array of PolicyData structures containing ERC1271 policy information
     */
    function enableERC1271Policies(PermissionId permissionId, ERC7739Data calldata erc1271Policies) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        // Enable the ERC1271 policies
        $enabledERC7739Content.enable({
            contents: erc1271Policies.allowedERC7739Content,
            permissionId: permissionId,
            smartAccount: msg.sender
        });
        $erc1271Policies.enable({
            policyType: PolicyType.ERC1271,
            permissionId: permissionId,
            configId: permissionId.toErc1271PolicyId().toConfigId(),
            policyDatas: erc1271Policies.erc1271Policies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    /**
     * @notice Disable specific ERC1271 policies and contents for a given permission
     * @param permissionId The unique identifier for the permission
     * @param policies An array of policy addresses to be disabled
     * @param contents An array of 7739 contents to be disabled
     */
    function disableERC1271Policies(PermissionId permissionId, address[] calldata policies, string[] calldata contents) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        for (uint256 i; i < contents.length; ++i) {
            bytes32 contentHash = HashLib.hashERC7739Content(contents[i]);
            $enabledERC7739Content[permissionId].remove(msg.sender, contentHash);
        }

        // Disable the specified ERC1271 policies
        $erc1271Policies.disable({
            policyType: PolicyType.ERC1271,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });
    }

    /**
     * @notice Disable specific ERC1271 policies and contents for a given permission
     * @param permissionId The unique identifier for the permission
     */
    function disableERC1271Policies(PermissionId permissionId) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        $enabledERC7739Content[permissionId].removeAll(msg.sender);

        // Disable the specified ERC1271 policies
        $erc1271Policies.disableAll({
            policyType: PolicyType.ERC1271,
            smartAccount: msg.sender,
            permissionId: permissionId
        });
    }

    /**
     * @notice Enable action policies for a specific permission
     * @param permissionId The unique identifier for the permission
     * @param actionPolicies An array of ActionData structures containing action policy information
     */
    function enableActionPolicies(PermissionId permissionId, ActionData[] memory actionPolicies) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        // Enable the action policies
        $actionPolicies.enable({
            permissionId: permissionId,
            actionPolicyDatas: actionPolicies,
            smartAccount: msg.sender,
            useRegistry: true
        });
    }

    /**
     * @notice Disable specific action policies for a given permission and action ID
     * @param permissionId The unique identifier for the permission
     * @param actionId The specific action identifier
     */
    function disableActionId(PermissionId permissionId, ActionId actionId) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        // Disable all action policies for the given action ID
        $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(msg.sender);

        // remove action Id from enabledActionIds
        $actionPolicies.enabledActionIds[permissionId].remove(msg.sender, ActionId.unwrap(actionId));
        emit ISmartSession.ActionIdDisabled(permissionId, actionId, msg.sender);
    }

    /**
     * @notice Disable action id for a given permission and action ID
     * @param permissionId The unique identifier for the permission
     * @param actionId The specific action identifier
     * @param policies An array of policy addresses to be disabled
     */
    function disableActionPolicies(PermissionId permissionId, ActionId actionId, address[] calldata policies) public {
        // Check if the session is enabled for the caller and the given permission
        if ($enabledSessions.contains(msg.sender, PermissionId.unwrap(permissionId)) == false) {
            revert InvalidSession(permissionId);
        }

        // Disable the specified action policies for the given action ID
        $actionPolicies.actionPolicies[actionId].disable({
            policyType: PolicyType.ACTION,
            smartAccount: msg.sender,
            permissionId: permissionId,
            policies: policies
        });

        // remove the actionId from the enabledActionIds if no policies are left
        if ($actionPolicies.actionPolicies[actionId].policyList[permissionId].length(msg.sender) == 0) {
            $actionPolicies.enabledActionIds[permissionId].remove(msg.sender, ActionId.unwrap(actionId));
            emit ISmartSession.ActionIdDisabled(permissionId, actionId, msg.sender);
        }
    }

    /**
     * @notice Enable multiple sessions with their associated policies
     * @param sessions An array of Session structures to be enabled
     * @return permissionIds An array of PermissionId values corresponding to the enabled sessions
     */
    function enableSessions(Session[] calldata sessions) public returns (PermissionId[] memory permissionIds) {
        uint256 length = sessions.length;
        if (length == 0) revert InvalidData();

        permissionIds = new PermissionId[](length);

        for (uint256 i; i < length; i++) {
            Session calldata session = sessions[i];
            PermissionId permissionId = session.toPermissionId();

            // Add the session to the list of enabled sessions for the caller
            $enabledSessions.add({ account: msg.sender, value: PermissionId.unwrap(permissionId) });

            // Enable the ISessionValidator for this session
            $sessionValidators.enable({
                permissionId: permissionId,
                smartAccount: msg.sender,
                sessionValidator: session.sessionValidator,
                sessionValidatorConfig: session.sessionValidatorInitData,
                useRegistry: true
            });

            // Enable UserOp policies
            $userOpPolicies.enable({
                policyType: PolicyType.USER_OP,
                permissionId: permissionId,
                configId: permissionId.toUserOpPolicyId().toConfigId(),
                policyDatas: session.userOpPolicies,
                smartAccount: msg.sender,
                useRegistry: true
            });

            // Enable ERC1271 policies
            $erc1271Policies.enable({
                policyType: PolicyType.ERC1271,
                permissionId: permissionId,
                configId: permissionId.toErc1271PolicyId().toConfigId(),
                policyDatas: session.erc7739Policies.erc1271Policies,
                smartAccount: msg.sender,
                useRegistry: true
            });
            $enabledERC7739Content.enable(session.erc7739Policies.allowedERC7739Content, permissionId, msg.sender);

            // Enable Action policies
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

    /**
     * @notice Remove a session and all its associated policies
     * @param permissionId The unique identifier for the session to be removed
     */
    function removeSession(PermissionId permissionId) public {
        if (permissionId == EMPTY_PERMISSIONID) revert InvalidSession(permissionId);

        // Remove all UserOp policies for this session
        $userOpPolicies.policyList[permissionId].removeAll(msg.sender);

        // Remove all ERC1271 policies for this session
        $erc1271Policies.policyList[permissionId].removeAll(msg.sender);

        // Remove all Action policies for this session
        uint256 actionLength = $actionPolicies.enabledActionIds[permissionId].length(msg.sender);
        for (uint256 i; i < actionLength; i++) {
            ActionId actionId = ActionId.wrap($actionPolicies.enabledActionIds[permissionId].at(msg.sender, i));
            $actionPolicies.actionPolicies[actionId].policyList[permissionId].removeAll(msg.sender);
        }

        // removing all stored actionIds
        $actionPolicies.enabledActionIds[permissionId].removeAll(msg.sender);

        $sessionValidators.disable({ permissionId: permissionId, smartAccount: msg.sender });

        // Remove all ERC1271 policies for this session
        $enabledSessions.remove({ account: msg.sender, value: PermissionId.unwrap(permissionId) });
        $enabledERC7739Content[permissionId].removeAll(msg.sender);
        emit SessionRemoved(permissionId, msg.sender);
    }

    /**
     * Initialize the module with the given data
     *
     * @param data The data to initialize the module with
     */
    function onInstall(bytes calldata data) external override {
        // Its possible that the module was installed before and when uninstalling the module, the smart session storage
        // for that smart account was not zero'ed correctly. In such cases, we need to check if the smart account has
        // still some enabled permissions / sessions set.
        // re-enabling these sessions will cause the smart account to be in the same state as before, potentially
        // activating sessions that the user thought were terminated. This MUST be avoided.
        // if this case happens, it's not possible for the account to install the module again, unless the account calls
        // into the removreSession functions to disable all dangling permissions
        if ($enabledSessions.length({ account: msg.sender }) > 0) {
            revert SmartSessionModuleAlreadyInstalled(msg.sender);
        }
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
     * De-initialize the module with the given data.
     * All PermissionIds will be wiped from storage
     */
    function onUninstall(bytes calldata /*data*/ ) external override {
        uint256 configIdsCnt = $enabledSessions.length({ account: msg.sender });

        for (uint256 i; i < configIdsCnt; i++) {
            // always remove index 0 since the array is shifted down when the first item is removed
            PermissionId configId = PermissionId.wrap($enabledSessions.at({ account: msg.sender, index: 0 }));
            removeSession(configId);
        }
    }

    function isInitialized(address smartAccount) external view override returns (bool) {
        uint256 configIdsCnt = $enabledSessions.length({ account: smartAccount });
        return configIdsCnt > 0;
    }

    function isModuleType(uint256 typeID) external pure override returns (bool) {
        if (typeID == ERC7579_MODULE_TYPE_VALIDATOR) return true;
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

    function isPermissionEnabled(PermissionId permissionId, address account) external view returns (bool) {
        return $enabledSessions.contains(account, PermissionId.unwrap(permissionId));
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
