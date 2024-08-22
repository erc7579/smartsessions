// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./utils/AssociatedArrayLib.sol";
import "./interfaces/ISigner.sol";
import { EnumerableSet } from "./utils/EnumerableSet4337.sol";
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

struct Session {
    ISigner isigner;
    bytes32 salt;
    bytes isignerInitData;
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    ActionData[] actions;
}

struct EnableSessions {
    uint8 sessionIndex;
    bytes hashesAndChainIds;
    Session sessionToEnable;
    bytes permissionEnableSig;
}

struct PolicyData {
    address policy;
    bytes initData;
}

struct ActionData {
    ActionId actionId;
    PolicyData[] actionPolicies;
}

struct ERC7739Data {
    string[] allowedERC7739Content;
    PolicyData[] erc1271Policies;
}

////////////////////////

struct UninstallSessions {
    SignerId signerId;
}

enum SmartSessionMode {
    USE,
    ENABLE,
    UNSAFE_ENABLE,
    ENABLE_ADD_POLICIES,
    UNSAFE_ENABLE_ADD_POLICIES
}

enum PolicyType {
    USER_OP,
    ACTION,
    ERC1271
}

struct Policy {
    mapping(SignerId => EnumerableSet.AddressSet) policyList;
}

struct EnumerableActionPolicy {
    mapping(ActionId => Policy) actionPolicies;
    mapping(SignerId => AssociatedArrayLib.Bytes32Array) enabledActionIds;
}

type ValidationData is uint256;

ValidationData constant ERC4377_VALIDATION_SUCCESS = ValidationData.wrap(0);
ValidationData constant ERC4337_VALIDATION_FAILED = ValidationData.wrap(1);
bytes4 constant EIP1271_SUCCESS = 0x1626ba7e;
bytes4 constant EIP1271_FAILED = 0xFFFFFFFF;

uint256 constant ERC7579_MODULE_TYPE_VALIDATOR = 1;
uint256 constant ERC7579_MODULE_TYPE_EXECUTOR = 2;
uint256 constant ERC7579_MODULE_TYPE_FALLBACK = 3;
uint256 constant ERC7579_MODULE_TYPE_HOOK = 4;
