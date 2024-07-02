import "../DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "./ArrayMap4337Lib.sol";
import "../interfaces/IPolicy.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { Bytes32ArrayMap4337, ArrayMap4337Lib } from "./ArrayMap4337Lib.sol";
import "forge-std/console2.sol";

library ConfigLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ConfigLib for *;
    using ArrayMap4337Lib for *;

    function safePush(SentinelList4337Lib.SentinelList storage self, address account, address newEntry) internal {
        if (!self.alreadyInitialized(account)) {
            self.init({ account: account });
        }

        if (!self.contains(account, newEntry)) {
            self.push({ account: account, newEntry: newEntry });
        }
    }

    function enable(Policy storage $policy, PolicyConfig[] memory policyConfig, address smartAccount) internal {
        uint256 lengthConfigs = policyConfig.length;

        for (uint256 i; i < lengthConfigs; i++) {
            PolicyConfig memory config = policyConfig[i];
            uint256 lengthPolicies = config.policies.length;

            address policy = config.policies[i].policy;
            // policy.initFwd({id: id, smartAccount: smartAccount});

            for (uint256 y; y < lengthPolicies; y++) {
                IPolicyInit(policy).initForAccount({
                    account: msg.sender,
                    id: sessionId(config.signerId),
                    initData: config.policies[i].initData
                });
                $policy.policyList[config.signerId].safePush(smartAccount, policy);
            }
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        ActionPolicyConfig[] memory actionPolicyConfig,
        address smartAccount
    )
        internal
    {
        uint256 length = actionPolicyConfig.length;

        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionPolicyConfig memory config = actionPolicyConfig[i];
            $self.enabledActionIds.push(smartAccount, ActionId.unwrap(config.actionId));
            $self.actionPolicies[config.actionId].enable(config.policyConfig, smartAccount);
        }
    }

    function enable(
        EnumerableActionPolicy storage $self,
        PolicyData[] memory policies,
        ActionId actionId,
        SignerId signerId,
        address smartAccount
    )
        internal
    {
        $self.enabledActionIds.push(smartAccount, ActionId.unwrap(actionId));
        $self.actionPolicies[actionId].enable(policies, signerId, smartAccount);
    }

    function enable(
        Policy storage $policy,
        PolicyData[] memory policies,
        SignerId signerId,
        address smartAccount
    )
        internal
    {
        uint256 lengthPolicies = policies.length;

        for (uint256 i; i < lengthPolicies; i++) {
            $policy.policyList[signerId].safePush(smartAccount, policies[i].policy);
            IPolicyInit(policies[i].policy).initForAccount({
                account: msg.sender,
                id: sessionId(signerId),
                initData: policies[i].initData
            });
        }
    }
}
