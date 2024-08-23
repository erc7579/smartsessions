// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ISubPermission } from "../interfaces/IPolicy.sol";
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
     * Generic function to enable policies for a permissionId
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
            if (!ISubPermission(policy).supportsInterface(type(ISubPermission).interfaceId)) {
                revert UnsupportedPolicy(policy);
            }

            // this will revert if the policy is not attested to
            if (useRegistry) {
                registry.checkForAccount({ smartAccount: smartAccount, module: policy, moduleType: POLICY_MODULE_TYPE });
            }

            $policy.policyList[permissionId].add({ account: smartAccount, value: policy });
            ISubPermission(policy).initializeWithMultiplexer({
                account: smartAccount,
                configId: configId,
                initData: policyDatas[i].initData
            });

            emit ISmartSession.PolicyEnabled(permissionId, policyType, policy, smartAccount);
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        PermissionId permissionId,
        ActionData[] memory actionPolicyDatas,
        address smartAccount,
        bool useRegistry
    )
        internal
    {
        uint256 length = actionPolicyDatas.length;
        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionData memory actionPolicyData = actionPolicyDatas[i];
            ActionId actionId = actionPolicyData.actionId;
            $self.enabledActionIds[permissionId].push(smartAccount, ActionId.unwrap(actionId));
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
