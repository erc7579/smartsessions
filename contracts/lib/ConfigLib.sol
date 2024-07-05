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

    error UnsupportedPolicy(address policy);

    function safePush(SentinelList4337Lib.SentinelList storage self, address account, address newEntry) internal {
        if (!self.alreadyInitialized(account)) {
            self.init({ account: account });
        }

        if (!self.contains(account, newEntry)) {
            self.push({ account: account, newEntry: newEntry });
        }
    }

    // NOTE: ok
    function enable(
        Policy storage $policy,
        SignerId signerId,
        PolicyData[] memory policyDatas,
        address smartAccount
    )
        internal
    {
        uint256 lengthConfigs = policyDatas.length;

        // iterage over all policyData
        for (uint256 i; i < lengthConfigs; i++) {
            PolicyData memory policyData = policyDatas[i];

            IPolicyInit policy = IPolicyInit(policyData.policy);
            if (!policy.supportsInterface(type(IPolicyInit).interfaceId)) revert UnsupportedPolicy(address(policy));

            // initialize sub policy for account
            IPolicyInit(policy).initForAccount({
                account: smartAccount,
                id: sessionId(signerId),
                initData: policyData.initData
            });
            $policy.policyList[signerId].safePush(smartAccount, address(policy));
        }
    }

    // NOTE: ok
    function enable(
        EnumerableActionPolicy storage $self,
        SignerId signerId,
        ActionData[] memory actionPolicyDatas,
        address smartAccount
    )
        internal
    {
        uint256 length = actionPolicyDatas.length;

        for (uint256 i; i < length; i++) {
            // record every enabled actionId
            ActionData memory actionPolicyData = actionPolicyDatas[i];
            $self.enabledActionIds.push(smartAccount, ActionId.unwrap(actionPolicyData.actionId));
            $self.actionPolicies[actionPolicyData.actionId].enable(
                signerId, actionPolicyData.actionPolicies, smartAccount
            );
        }
    }

    // function enable(
    //     EnumerableActionPolicy storage $self,
    //     PolicyData[] memory policies,
    //     ActionId actionId,
    //     SignerId signerId,
    //     address smartAccount
    // )
    //     internal
    // {
    //     $self.enabledActionIds.push(smartAccount, ActionId.unwrap(actionId));
    //     $self.actionPolicies[actionId].enable(policies, signerId, smartAccount);
    // }

    // function enable(
    //     Policy storage $policy,
    //     PolicyData[] memory policies,
    //     SignerId signerId,
    //     address smartAccount
    // )
    //     internal
    // {
    //     uint256 lengthPolicies = policies.length;
    //
    //     for (uint256 i; i < lengthPolicies; i++) {
    //         $policy.policyList[signerId].safePush(smartAccount, policies[i].policy);
    //         IPolicyInit(policies[i].policy).initForAccount({
    //             account: msg.sender,
    //             id: sessionId(signerId),
    //             initData: policies[i].initData
    //         });
    //     }
    // }
}
