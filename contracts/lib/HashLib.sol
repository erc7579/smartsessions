// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";

// Define the type hash for PolicyData
bytes32 constant POLICY_DATA_TYPEHASH = keccak256("PolicyData(address policy,bytes initData)");
bytes32 constant ACTION_POLICY_DATA_TYPEHASH = keccak256("ActionPolicy(bytes32 actionId,PolicyData[] actionPolicies)PolicyData(address policy,bytes initData)");

// Define the type hash for SignerData
bytes32 constant SIGNER_DATA_TYPEHASH =
    keccak256("SignerData(address isigner,PolicyData[] actionPolicies), PolicyData(address policy,bytes initData)");

// Define the type hash for EnableSessions
bytes32 constant ENABLE_SESSIONS_TYPEHASH = keccak256(
    "EnableSessions(address isigner,bytes isignerInitData,PolicyData[] userOpPolicies,PolicyData[] erc1271Policies,ActionData[] actions,bytes permissionEnableSig,uint256 nonce)PolicyData(address policy,bytes initData)ActionData(bytes32 actionId,PolicyData[] actionPolicies)"
);

library HashLib {
    function digest(EnableSessions memory enableSession, uint256 nonce) internal pure returns (bytes32 _hash) {
        _hash = keccak256(
            abi.encode(
                ENABLE_SESSIONS_TYPEHASH,
                address(enableSession.isigner),
                keccak256(enableSession.isignerInitData),
                hashPolicyDataArray(enableSession.userOpPolicies),
                hashPolicyDataArray(enableSession.erc1271Policies),
                hashActionDataArray(enableSession.actions),
                keccak256(enableSession.permissionEnableSig),
                nonce
            )
        );
    }

    function hashPolicyData(PolicyData memory policyData) internal pure returns (bytes32) {
        return keccak256(abi.encode(POLICY_DATA_TYPEHASH, policyData.policy, keccak256(policyData.initData)));
    }

    function hashPolicyDataArray(PolicyData[] memory policyDataArray) internal pure returns (bytes32) {
        uint256 length = policyDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashPolicyData(policyDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashActionDataArray(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashActionData(actionDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashActionData(ActionData memory actionData) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(ACTION_POLICY_DATA_TYPEHASH, actionData.actionId, hashPolicyDataArray(actionData.actionPolicies))
        );
    }
}
