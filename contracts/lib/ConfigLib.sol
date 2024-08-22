// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
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
     * Generic function to enable policies for a signerId
     */
    function enable(
        Policy storage $policy,
        PolicyType policyType,
        SignerId signerId,
        SessionId sessionId,
        PolicyData[] memory policyDatas,
        address smartAccount,
        bool useRegistry
    )
        internal
    {
        // iterage over all policyData
        uint256 lengthConfigs = policyDatas.length;
        for (uint256 i; i < lengthConfigs; i++) {
            PolicyData memory policyData = policyDatas[i];

            ISubPermission policy = ISubPermission(policyData.policy);

            if (!policy.supportsInterface(type(ISubPermission).interfaceId)) revert UnsupportedPolicy(address(policy));

            if (useRegistry) registry.checkForAccount(smartAccount, address(policy), POLICY_MODULE_TYPE);

            ISubPermission(policy).onInstall({ data: abi.encodePacked(sessionId, smartAccount, policyData.initData) });

            $policy.policyList[signerId].add(smartAccount, address(policy));
            emit ISmartSession.PolicyEnabled(signerId, policyType, address(policy), smartAccount);
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        SignerId signerId,
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
            $self.enabledActionIds[signerId].push(smartAccount, ActionId.unwrap(actionId));
            $self.actionPolicies[actionId].enable({
                policyType: PolicyType.ACTION,
                signerId: signerId,
                sessionId: signerId.toSessionId(actionId),
                policyDatas: actionPolicyData.actionPolicies,
                smartAccount: smartAccount,
                useRegistry: useRegistry
            });
        }
    }

    function enable(
        mapping(SessionId => mapping(bytes32 => mapping(address => bool))) storage $enabledERC7739Content,
        string[] memory contents,
        SessionId sessionId,
        address smartAccount
    )
        internal
    {
        uint256 length = contents.length;
        for (uint256 i; i < length; i++) {
            bytes32 contentHash = contents[i].hashERC7739Content();
            $enabledERC7739Content[sessionId][contentHash][smartAccount] = true;
        }
    }

    function disable(
        Policy storage $policy,
        PolicyType policyType,
        address smartAccount,
        SignerId signerId,
        address[] calldata policies
    )
        internal
    {
        uint256 length = policies.length;
        for (uint256 i; i < length; i++) {
            address policy = policies[i];
            $policy.policyList[signerId].remove(smartAccount, policy);
            emit ISmartSession.PolicyDisabled(signerId, policyType, address(policy), smartAccount);
        }
    }
}
