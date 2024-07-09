// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./lib/ArrayMap4337Lib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import "./interfaces/ISigner.sol";

type SignerId is bytes32;

type ActionId is bytes32;

type UserOpPolicyId is bytes32;
type ActionPolicyId is bytes32;
type Erc1271PolicyId is bytes32;


// type SignedActionId is bytes32;

type SessionId is bytes32;

function toSignerId(address account, ISigner isigner) view returns (SignerId signerId) {
    signerId = SignerId.wrap(keccak256(abi.encodePacked("Signer Id for ", account, address(isigner), block.timestamp)));
}

function toUserOpPolicyId(SignerId signerId) view returns (UserOpPolicyId userOpPolicyId) {
    userOpPolicyId = UserOpPolicyId.wrap(SignerId.unwrap(signerId));
}

function toActionId(address target, bytes calldata data) pure returns (ActionId actionId) {
    actionId = ActionId.wrap(keccak256(abi.encodePacked(target, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0))));
}

function toActionPolicyId(SignerId signerId, ActionId actionId) pure returns (ActionPolicyId policyId) {
    policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(signerId, actionId)));
}

function toErc1271PolicyId(SignerId signerId) view returns (Erc1271PolicyId erc1271PolicyId) {
    erc1271PolicyId = Erc1271PolicyId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", signerId))
    );
}

/* function toSignedActionId(SignerId signerId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", SignerId.unwrap(signerId), ActionId.unwrap(actionId)))
    );
} */

function sessionId(SignerId signerId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, signerId)));
}

function sessionId(UserOpPolicyId userOpPolicyId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, userOpPolicyId)));
}

function sessionId(ActionPolicyId actionPolicyId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, actionPolicyId)));
}

function sessionId(SignerId signerId, ActionId actionId) view returns (SessionId _id) {
    _id = sessionId(toActionPolicyId(signerId, actionId));
}

function sessionId(Erc1271PolicyId erc1271PolicyId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, erc1271PolicyId)));
}

// InstallSessions[] sessions;

struct InstallSessions {
    SignerId signerId;
    PolicyData[] userOpPolicies;
    PolicyData[] erc1271Policies;
    ActionData[] actions;
}

struct EnableSessions {
    // SignerID is be part of the packedSig, so doesnt have to be in here
    ISigner isigner;
    bytes isignerInitData;
    PolicyData[] userOpPolicies;
    PolicyData[] erc1271Policies;
    ActionData[] actions;
    bytes permissionEnableSig;
}

// TODO: add this to session structs
struct SignerData {
    ISigner isigner;
    bytes isignerInitData;
}

struct PolicyData {
    address policy;
    bytes initData;
}

struct ActionData {
    ActionId actionId;
    PolicyData[] actionPolicies;
}

////////////////////////

struct UninstallSessions {
    SignerId signerId;
}

enum SmartSessionMode {
    USE,
    ENABLE,
    UNSAFE_ENABLE
}

struct Policy {
    mapping(SignerId => SentinelList4337Lib.SentinelList) policyList;
}

struct EnumerableActionPolicy {
    mapping(ActionId => Policy) actionPolicies;
    Bytes32ArrayMap4337 enabledActionIds;
}
