// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { IPolicy, IUserOpPolicy, IActionPolicy, I1271Policy } from "../interfaces/IPolicy.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { IRegistry, ModuleType } from "../interfaces/IRegistry.sol";
import { IdLib } from "./IdLib.sol";
import { HashLib } from "./HashLib.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";

library ConfigLib {
    using FlatBytesLib for FlatBytesLib.Bytes;
    using EnumerableSet for EnumerableSet.AddressSet;
    using EnumerableSet for EnumerableSet.Bytes32Set;
    using HashLib for string;
    using IdLib for *;
    using ConfigLib for *;

    error UnsupportedPolicy(address policy);

    function requirePolicyType(address policy, PolicyType policyType) internal view {
        bool supportsInterface;
        if (policyType == PolicyType.USER_OP) {
            supportsInterface = IPolicy(policy).supportsInterface(type(IUserOpPolicy).interfaceId);
        } else if (policyType == PolicyType.ACTION) {
            supportsInterface = IPolicy(policy).supportsInterface(type(IActionPolicy).interfaceId);
        } else if (policyType == PolicyType.ERC1271) {
            supportsInterface = IPolicy(policy).supportsInterface(type(I1271Policy).interfaceId);
        } else {
            revert UnsupportedPolicy(policy);
        }

        // Revert if the policy does not support the required interface
        if (!supportsInterface) {
            revert UnsupportedPolicy(policy);
        }
    }

    /**
     * Enables policies for a given permission ID.
     *
     * @dev This function iterates through the provided policy data and enables each policy.
     *      It checks if the policy supports the IPolicy interface, verifies it with the registry if required,
     *      adds it to the policy list, initializes it, and emits an event.
     *
     * @param $policy The storage reference to the Policy struct.
     * @param policyType The type of policy being enabled defined as erc-7579 module type
     * @param permissionId The identifier of the permission for which policies are being enabled.
     * @param configId The configuration ID associated with the permission and policy type.
     * @param policyDatas An array of PolicyData structs containing policy addresses and initialization data.
     * @param smartAccount The address of the smart account for which policies are being enabled.
     * @param useRegistry A boolean flag indicating whether to check policies against the registry.
     */
    function enable(
        Policy storage $policy,
        PolicyType policyType,
        PermissionId permissionId,
        ConfigId configId,
        PolicyData[] memory policyDatas,
        address smartAccount,
        bool useRegistry
    )
        internal
    {
        // iterage over all policyData
        uint256 lengthConfigs = policyDatas.length;
        for (uint256 i; i < lengthConfigs; i++) {
            address policy = policyDatas[i].policy;

            policy.requirePolicyType(policyType);

            // this will revert if the policy is not attested to
            if (useRegistry) {
                registry.checkForAccount({ smartAccount: smartAccount, module: policy });
            }

            // Add the policy to the list for the given permission and smart account
            $policy.policyList[permissionId].add({ account: smartAccount, value: policy });

            // Initialize the policy with the provided configuration
            // overwrites the config
            IPolicy(policy).initializeWithMultiplexer({
                account: smartAccount,
                configId: configId,
                initData: policyDatas[i].initData
            });

            emit ISmartSession.PolicyEnabled(permissionId, policyType, policy, smartAccount);
        }
    }

    /**
     * Enables action policies for a given permission ID.
     *
     * @dev This function iterates through the provided action policy data and enables each action policy.
     *      It records enabled action IDs and calls the enable function for each action policy.
     *
     * @param $self The storage reference to the EnumerableActionPolicy struct.
     * @param permissionId The identifier of the permission for which action policies are being enabled.
     * @param actionPolicyDatas An array of ActionData structs containing action policy information.
     * @param smartAccount The address of the smart account for which action policies are being enabled.
     * @param useRegistry A boolean flag indicating whether to check policies against the registry.
     */
    function enable(
        EnumerableActionPolicy storage $self,
        PermissionId permissionId,
        ActionData[] memory actionPolicyDatas,
        address smartAccount,
        bool useRegistry
    )
        internal
    {
        if (permissionId == EMPTY_PERMISSIONID) revert ISmartSession.InvalidPermissionId(permissionId);
        uint256 length = actionPolicyDatas.length;
        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionData memory actionPolicyData = actionPolicyDatas[i];

            // disallow actions to be set for address(0) or to the smartsession module itself
            // sessionkeys that have access to smartsessions, may use this access to elevate their privileges
            if (actionPolicyData.actionTarget == address(0) || actionPolicyData.actionTarget == address(this)) {
                revert ISmartSession.InvalidActionId();
            }
            ActionId actionId = actionPolicyData.actionTarget.toActionId(actionPolicyData.actionTargetSelector);
            if (actionId == EMPTY_ACTIONID) revert ISmartSession.InvalidActionId();

            // Record the enabled action ID
            $self.enabledActionIds[permissionId].add(smartAccount, ActionId.unwrap(actionId));

            // Record the enabled action ID
            $self.actionPolicies[actionId].enable({
                policyType: PolicyType.ACTION,
                permissionId: permissionId,
                configId: permissionId.toConfigId(actionId),
                policyDatas: actionPolicyData.actionPolicies,
                smartAccount: smartAccount,
                useRegistry: useRegistry
            });
        }
    }

    /**
     * Enables ERC7739 content for a given configuration ID and smart account.
     *
     * @dev This function marks the provided content as enabled for the specified configuration and smart account.
     *
     * @param $enabledERC7739Content The storage mapping for enabled ERC7739 content.
     * @param contents An array of strings representing the content to be enabled.
     * @param permissionId The configuration ID associated with the content.
     * @param smartAccount The address of the smart account for which the content is being enabled.
     */
    function enable(
        mapping(PermissionId permissionId => EnumerableSet.Bytes32Set) storage $enabledERC7739Content,
        string[] memory contents,
        PermissionId permissionId,
        address smartAccount
    )
        internal
    {
        uint256 length = contents.length;
        for (uint256 i; i < length; i++) {
            bytes32 contentHash = contents[i].hashERC7739Content();
            $enabledERC7739Content[permissionId].add(smartAccount, contentHash);
        }
    }

    /**
     * @notice Enable and configure an ISessionValidator for a specific permission and account
     * @dev This function sets up the session validator and stores its configuration
     * @param permissionId The unique identifier for the permission
     * @param smartAccount The account address for which the validator is being set
     * @param sessionValidator The ISessionValidator contract to be enabled
     * @param sessionValidatorConfig The configuration data for the session validator
     */
    function enable(
        mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) storage
            $sessionValidators,
        PermissionId permissionId,
        address smartAccount,
        ISessionValidator sessionValidator,
        bytes memory sessionValidatorConfig,
        bool useRegistry
    )
        internal
    {
        // Check if the sessionValidator is valid and supports the required interface
        if (
            address(sessionValidator) == address(0)
                || !sessionValidator.isModuleType(ERC7579_MODULE_TYPE_STATELESS_VALIDATOR)
        ) {
            revert ISmartSession.InvalidISessionValidator(sessionValidator);
        }

        // this will revert if the policy is not attested to
        if (useRegistry) {
            registry.checkForAccount({
                smartAccount: smartAccount,
                module: address(sessionValidator),
                moduleType: ModuleType.wrap(ERC7579_MODULE_TYPE_STATELESS_VALIDATOR)
            });
        }

        // Get the storage reference for the signer configuration
        SignerConf storage $conf = $sessionValidators[permissionId][smartAccount];
        // Set the session validator
        $conf.sessionValidator = sessionValidator;

        // Store the signer configuration
        $conf.config.store(sessionValidatorConfig);
        emit ISmartSession.SessionValidatorEnabled(permissionId, address(sessionValidator), smartAccount);
    }

    /**
     * Disables specified policies for a given permission ID and smart account.
     *
     * @dev This function removes the specified policies from the policy list and emits events for each disabled policy.
     * @notice Cleaning state on policies is not required as on enable, initializeWithMultiplexer is called which MUST
     *       overwrite the current state.
     *
     * @param $policy The storage reference to the Policy struct.
     * @param policyType The type of policy being disabled defined as ERC-7579 module type
     * @param smartAccount The address of the smart account for which policies are being disabled.
     * @param permissionId The identifier of the permission for which policies are being disabled.
     * @param policies An array of policy addresses to be disabled.
     */
    function disable(
        Policy storage $policy,
        PolicyType policyType,
        address smartAccount,
        PermissionId permissionId,
        address[] calldata policies
    )
        internal
    {
        uint256 length = policies.length;
        for (uint256 i; i < length; i++) {
            address policy = policies[i];
            $policy.policyList[permissionId].remove(smartAccount, policy);
            emit ISmartSession.PolicyDisabled(permissionId, policyType, address(policy), smartAccount);
        }
    }

    function disable(
        mapping(PermissionId permissionId => mapping(address smartAccount => SignerConf conf)) storage
            $sessionValidators,
        PermissionId permissionId,
        address smartAccount
    )
        internal
    {
        // Get the storage reference for the signer configuration
        SignerConf storage $conf = $sessionValidators[permissionId][smartAccount];

        //emit event
        emit ISmartSession.SessionValidatorDisabled(permissionId, address($conf.sessionValidator), smartAccount);

        // Clear the session validator
        delete $conf.sessionValidator;

        // clear the signer configuration
        $conf.config.clear();
    }
}
