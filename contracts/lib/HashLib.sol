// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import "forge-std/console2.sol";
import { LibZip } from "solady/utils/LibZip.sol";
import { ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";

// Define the type hash for PolicyData
bytes32 constant POLICY_DATA_TYPEHASH = keccak256("PolicyData(address policy,bytes initData)");

// Define the type hash for SignerData
bytes32 constant SIGNER_DATA_TYPEHASH = keccak256("SignerData(address isigner,bytes isignerInitData)");

// Define the type hash for EnableSessions
bytes32 constant ENABLE_SESSIONS_TYPEHASH = keccak256(
    "EnableSessions(SignerData signer,PolicyData[] userOpPolicies,PolicyData[] erc1271Policies,ActionData[] actions,bytes permissionEnableSig)SignerData(address isigner,bytes isignerInitData)PolicyData(address policy,bytes initData)"
);

library HashLib {
    function hashEnableSession(
        EnableSessions memory enableSession,
        uint256 nonce
    )
        internal
        pure
        returns (bytes32 _hash)
    {
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
        bytes32[] memory hashes = new bytes32[](policyDataArray.length);
        for (uint256 i = 0; i < policyDataArray.length; i++) {
            hashes[i] = hashPolicyData(policyDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashActionDataArray(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        bytes32[] memory hashes = new bytes32[](actionDataArray.length);
        for (uint256 i = 0; i < actionDataArray.length; i++) {
            hashes[i] = hashActionData(actionDataArray[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    // Note: You'll need to implement this function based on your ActionData struct
    function hashActionData(ActionData memory actionData) internal pure returns (bytes32) {
        // Implement this based on your ActionData struct
        // For example:
        // return keccak256(abi.encode(
        //     ACTION_DATA_TYPEHASH,
        //     actionData.field1,
        //     actionData.field2,
        //     ...
        // ));
    }
}
