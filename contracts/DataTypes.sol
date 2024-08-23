// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./utils/AssociatedArrayLib.sol";
import "./interfaces/ISessionValidator.sol";
import { EnumerableSet } from "./utils/EnumerableSet4337.sol";
import { FlatBytesLib } from "@rhinestone/flatbytes/src/BytesLib.sol";

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                       Parameters                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

struct Session {
    ISessionValidator sessionValidator;
    bytes32 salt;
    bytes sessionValidatorInitData;
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    ActionData[] actions;
}

struct EnableSession {
    uint8 chainDigestIndex;
    ChainDigest[] hashesAndChainIds;
    Session sessionToEnable;
    bytes permissionEnableSig;
}

struct ChainSession {
    uint64 chainId;
    Session session;
}

struct MultiChainSession {
    ChainSession[] sessionsAndChainIds;
}

struct ChainDigest {
    uint64 chainId;
    bytes32 sessionDigest;
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

enum SmartSessionMode {
    USE,
    ENABLE,
    UNSAFE_ENABLE,
    ENABLE_ADD_POLICIES,
    UNSAFE_ENABLE_ADD_POLICIES
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                         Storage                            */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

struct SignerConf {
    ISessionValidator sessionValidator;
    uint48 validUntil;
    FlatBytesLib.Bytes config;
}

struct Policy {
    mapping(PermissionId => EnumerableSet.AddressSet) policyList;
}

struct EnumerableActionPolicy {
    mapping(ActionId => Policy) actionPolicies;
    mapping(PermissionId => AssociatedArrayLib.Bytes32Array) enabledActionIds;
}

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                 Custom Types & Constants                   */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/
enum PolicyType {
    USER_OP,
    ACTION,
    ERC1271
}

type PermissionId is bytes32;

type ActionId is bytes32;

type UserOpPolicyId is bytes32;

type ActionPolicyId is bytes32;

type Erc1271PolicyId is bytes32;

type ConfigId is bytes32;

type ValidationData is uint256;

ValidationData constant ERC4377_VALIDATION_SUCCESS = ValidationData.wrap(0);
ValidationData constant ERC4337_VALIDATION_FAILED = ValidationData.wrap(1);
bytes4 constant EIP1271_SUCCESS = 0x1626ba7e;
bytes4 constant EIP1271_FAILED = 0xFFFFFFFF;

uint256 constant ERC7579_MODULE_TYPE_VALIDATOR = 1;
uint256 constant ERC7579_MODULE_TYPE_EXECUTOR = 2;
uint256 constant ERC7579_MODULE_TYPE_FALLBACK = 3;
uint256 constant ERC7579_MODULE_TYPE_HOOK = 4;

using { permissionIdEq as == } for PermissionId global;
using { permissionIdNeq as != } for PermissionId global;

function permissionIdEq(PermissionId uid1, PermissionId uid2) pure returns (bool) {
    return PermissionId.unwrap(uid1) == PermissionId.unwrap(uid2);
}

function permissionIdNeq(PermissionId uid1, PermissionId uid2) pure returns (bool) {
    return PermissionId.unwrap(uid1) != PermissionId.unwrap(uid2);
}
