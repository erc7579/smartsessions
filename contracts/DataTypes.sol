// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./utils/AssociatedArrayLib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";
import "./interfaces/ISigner.sol";
import "forge-std/console2.sol";
import { FlatBytesLib } from "@rhinestone/flatbytes/src/BytesLib.sol";

type SignerId is bytes32;

using { signerIdEq as == } for SignerId global;
using { signerIdNeq as != } for SignerId global;

function signerIdEq(SignerId uid1, SignerId uid2) pure returns (bool) {
    return SignerId.unwrap(uid1) == SignerId.unwrap(uid2);
}

function signerIdNeq(SignerId uid1, SignerId uid2) pure returns (bool) {
    return SignerId.unwrap(uid1) != SignerId.unwrap(uid2);
}

type ActionId is bytes32;

type UserOpPolicyId is bytes32;

type ActionPolicyId is bytes32;

type Erc1271PolicyId is bytes32;

// type SignedActionId is bytes32;

type SessionId is bytes32;

// =====

struct SignerConf {
    ISigner isigner;
    uint48 validUntil;
    FlatBytesLib.Bytes config;
}

struct EnableSessions {
    ISigner isigner;
    bytes32 salt;
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
    mapping(SignerId => AssociatedArrayLib.Bytes32Array) enabledActionIds;
}
