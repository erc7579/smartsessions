// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { IPolicy } from "../interfaces/IPolicy.sol";
import { ISmartSession } from "../ISmartSession.sol";
import { AssociatedArrayLib } from "../utils/AssociatedArrayLib.sol";
import { IRegistry, ModuleType } from "../interfaces/IRegistry.sol";
import { IdLib } from "./IdLib.sol";
import { HashLib } from "./HashLib.sol";
import { EnumerableSet } from "../utils/EnumerableSet4337.sol";

library ConfigLib {
    using EnumerableSet for EnumerableSet.AddressSet;
    using HashLib for *;
    using ConfigLib for *;
    using AssociatedArrayLib for *;
    using IdLib for *;

    error UnsupportedPolicy(address policy);

    IRegistry internal constant registry = IRegistry(0x000000000069E2a187AEFFb852bF3cCdC95151B2);
    ModuleType internal constant POLICY_MODULE_TYPE = ModuleType.wrap(7);

    /**
     * Enables policies for a given permission ID.
     *
     * @dev This function iterates through the provided policy data and enables each policy.
     *      It checks if the policy supports the IPolicy interface, verifies it with the registry if required,
     *      adds it to the policy list, initializes it, and emits an event.
     *
     * @param $policy The storage reference to the Policy struct.
     * @param policyType The type of policy being enabled (e.g., USER_OP, ACTION, ERC1271).
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

            // TODO: can we remove this check?
            if (policy == address(0) || !IPolicy(policy).supportsInterface(type(IPolicy).interfaceId)) {
                revert UnsupportedPolicy(policy);
            }

            // this will revert if the policy is not attested to
            if (useRegistry) {
                registry.checkForAccount({ smartAccount: smartAccount, module: policy, moduleType: POLICY_MODULE_TYPE });
            }

            // Add the policy to the list for the given permission and smart account
            $policy.policyList[permissionId].add({ account: smartAccount, value: policy });

            // Initialize the policy with the provided configuration
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
            ActionId actionId = actionPolicyData.actionId;
            if (actionId == EMPTY_ACTIONID) revert ISmartSession.InvalidActionId();

            // Record the enabled action ID
            $self.enabledActionIds[permissionId].push(smartAccount, ActionId.unwrap(actionId));

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
     * @param configId The configuration ID associated with the content.
     * @param smartAccount The address of the smart account for which the content is being enabled.
     */
    function enable(
        mapping(ConfigId => mapping(bytes32 => mapping(address => bool))) storage $enabledERC7739Content,
        string[] memory contents,
        ConfigId configId,
        address smartAccount
    )
        internal
    {
        uint256 length = contents.length;
        for (uint256 i; i < length; i++) {
            bytes32 contentHash = contents[i].hashERC7739Content();
            $enabledERC7739Content[configId][contentHash][smartAccount] = true;
        }
    }

    /**
     * Disables specified policies for a given permission ID and smart account.
     *
     * @dev This function removes the specified policies from the policy list and emits events for each disabled policy.
     *
     * @param $policy The storage reference to the Policy struct.
     * @param policyType The type of policy being disabled (e.g., USER_OP, ACTION, ERC1271).
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
}
