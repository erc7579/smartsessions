// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

// Typehashes
bytes32 constant POLICY_DATA_TYPEHASH = keccak256("PolicyData(address policy,bytes initData)");
bytes32 constant ACTION_DATA_TYPEHASH =
    keccak256("ActionData(bytes32 actionId,PolicyData[] actionPolicies)PolicyData(address policy,bytes initData)");
bytes32 constant ERC7739_DATA_TYPEHASH = keccak256(
    "ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)PolicyData(address policy,bytes initData)"
);
bytes32 constant ENABLE_SESSIONS_TYPEHASH = keccak256(
    "EnableSessions(uint8 mode,address isigner,bytes32 salt,bytes isignerInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)PolicyData(address policy,bytes initData)ActionData(bytes32 actionId,PolicyData[] actionPolicies)ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)"
);

library HashLib {
    using EfficientHashLib for bytes32;
    using HashLib for *;

    function digest(
        EnableSessions memory enableSession,
        SmartSessionMode mode,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32 _hash)
    {
        _hash = keccak256(
            abi.encode(
                ENABLE_SESSIONS_TYPEHASH,
                uint8(mode), // Include mode as uint8
                address(enableSession.isigner),
                enableSession.salt,
                keccak256(enableSession.isignerInitData),
                enableSession.userOpPolicies.hashPolicyDataArray(),
                enableSession.erc7739Policies.hashERC7739Data(),
                enableSession.actions.hashActionDataArray(),
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
            hashes[i] = policyDataArray[i].hashPolicyData();
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashActionData(ActionData memory actionData) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(ACTION_DATA_TYPEHASH, actionData.actionId, hashPolicyDataArray(actionData.actionPolicies))
        );
    }

    function hashActionDataArray(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = actionDataArray[i].hashActionData();
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashERC7739Data(ERC7739Data memory erc7739Data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ERC7739_DATA_TYPEHASH,
                erc7739Data.allowedERC7739Content.hashStringArray(),
                erc7739Data.erc1271Policies.hashPolicyDataArray()
            )
        );
    }

    function hashStringArray(string[] memory stringArray) internal pure returns (bytes32) {
        uint256 length = stringArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = keccak256(abi.encodePacked(stringArray[i]));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashERC7739Content(string memory content) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(content));
    }
}
