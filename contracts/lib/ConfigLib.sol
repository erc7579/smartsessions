import "../DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "./ArrayMap4337Lib.sol";
import "../interfaces/IPolicy.sol";
import { SENTINEL, SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import { Bytes32ArrayMap4337, ArrayMap4337Lib } from "./ArrayMap4337Lib.sol";

library ConfigLib {
    using SentinelList4337Lib for SentinelList4337Lib.SentinelList;
    using ConfigLib for *;
    using ArrayMap4337Lib for *;

    error UnsupportedPolicy(address policy);

    event PolicyEnabled(SignerId signerId, address policy, address smartAccount);

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

            ISubPermission policy = ISubPermission(policyData.policy);
            if (!policy.supportsInterface(type(ISubPermission).interfaceId)) revert UnsupportedPolicy(address(policy));

            // initialize sub policy for account
            ISubPermission(policy).initForAccount({
                account: smartAccount,
                id: sessionId(signerId),
                initData: policyData.initData
            });

            $policy.policyList[signerId].safePush(smartAccount, address(policy));
            emit PolicyEnabled(signerId, address(policy), smartAccount);
        }
    }

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

    function disable(SentinelList4337Lib.SentinelList storage $self, SessionId _sessionId, address account) internal {
        (address[] memory entries,) = $self.getEntriesPaginated(account, SENTINEL, 32);

        uint256 length = entries.length;
        for (uint256 i; i < length; i++) {
            address entry = entries[i];
            ISubPermission(entry).deinitForAccount(account, _sessionId);
        }

        $self.popAll(account);
    }
}
