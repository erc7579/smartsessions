// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "./utils/AssociatedArrayLib.sol";
import "./interfaces/ISessionValidator.sol";
import { EnumerableSet } from "./utils/EnumerableSet4337.sol";
import { FlatBytesLib } from "@rhinestone/flatbytes/src/BytesLib.sol";

/*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
/*                       Parameters                           */
/*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

struct EnableSession {
    uint8 chainDigestIndex;
    ChainDigest[] hashesAndChainIds;
    Session sessionToEnable;
    // in order to enable a session, the smart account has to sign a digest. The signature for this is stored here.
    bytes permissionEnableSig;
}

struct ChainDigest {
    uint64 chainId;
    bytes32 sessionDigest;
}

struct Session {
    // every userOp has to be signed by the session key "owner".
    // the signature is validated via a stateless external contract: ISessionValidator, that can implement different
    // means of
    // validation.
    ISessionValidator sessionValidator;
    // the ISessionValidator contract can be configured with different parameters, that are passed in the
    // sessionValidatorInitData
    bytes sessionValidatorInitData;
    // A session key owner can have multiple sessions, with the same parameters. To facilitate this, a salt is necessary
    // to avoid collision
    bytes32 salt;
    // When every session can have multiple policies set.
    PolicyData[] userOpPolicies;
    ERC7739Data erc7739Policies;
    // A common usecase of session keys is to scope access to a speficic target and function selector. SmartSession
    // calls this "Action".
    // With ActionData we can specify policies that are only run, if a 7579 execution contains a specific action.
    ActionData[] actions;
}

struct MultiChainSession {
    ChainSession[] sessionsAndChainIds;
}

struct ChainSession {
    uint64 chainId;
    Session session;
}

// Policy data is a struct that contains the policy address and the initialization data for the policy.
struct PolicyData {
    address policy;
    bytes initData;
}

// Action data is a struct that contains the actionId and the policies that are associated with this action.
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
    UNSAFE_ENABLE
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

type ActionPolicyId is bytes32;

type UserOpPolicyId is bytes32;

type Erc1271PolicyId is bytes32;

type ConfigId is bytes32;

type ValidationData is uint256;

ActionId constant EMPTY_ACTIONID = ActionId.wrap(bytes32(0));
PermissionId constant EMPTY_PERMISSIONID = PermissionId.wrap(bytes32(0));
UserOpPolicyId constant EMPTY_USEROPPOLICYID = UserOpPolicyId.wrap(bytes32(0));
ActionPolicyId constant EMPTY_ACTIONPOLICYID = ActionPolicyId.wrap(bytes32(0));
Erc1271PolicyId constant EMPTY_ERC1271POLICYID = Erc1271PolicyId.wrap(bytes32(0));
ConfigId constant EMPTY_CONFIGID = ConfigId.wrap(bytes32(0));

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

// ActionId
using { actionIdEq as == } for ActionId global;
using { actionIdNeq as != } for ActionId global;

function actionIdEq(ActionId id1, ActionId id2) pure returns (bool) {
    return ActionId.unwrap(id1) == ActionId.unwrap(id2);
}

function actionIdNeq(ActionId id1, ActionId id2) pure returns (bool) {
    return ActionId.unwrap(id1) != ActionId.unwrap(id2);
}

// UserOpPolicyId
using { userOpPolicyIdEq as == } for UserOpPolicyId global;
using { userOpPolicyIdNeq as != } for UserOpPolicyId global;

function userOpPolicyIdEq(UserOpPolicyId id1, UserOpPolicyId id2) pure returns (bool) {
    return UserOpPolicyId.unwrap(id1) == UserOpPolicyId.unwrap(id2);
}

function userOpPolicyIdNeq(UserOpPolicyId id1, UserOpPolicyId id2) pure returns (bool) {
    return UserOpPolicyId.unwrap(id1) != UserOpPolicyId.unwrap(id2);
}

// ActionPolicyId
using { actionPolicyIdEq as == } for ActionPolicyId global;
using { actionPolicyIdNeq as != } for ActionPolicyId global;

function actionPolicyIdEq(ActionPolicyId id1, ActionPolicyId id2) pure returns (bool) {
    return ActionPolicyId.unwrap(id1) == ActionPolicyId.unwrap(id2);
}

function actionPolicyIdNeq(ActionPolicyId id1, ActionPolicyId id2) pure returns (bool) {
    return ActionPolicyId.unwrap(id1) != ActionPolicyId.unwrap(id2);
}

// Erc1271PolicyId
using { erc1271PolicyIdEq as == } for Erc1271PolicyId global;
using { erc1271PolicyIdNeq as != } for Erc1271PolicyId global;

function erc1271PolicyIdEq(Erc1271PolicyId id1, Erc1271PolicyId id2) pure returns (bool) {
    return Erc1271PolicyId.unwrap(id1) == Erc1271PolicyId.unwrap(id2);
}

function erc1271PolicyIdNeq(Erc1271PolicyId id1, Erc1271PolicyId id2) pure returns (bool) {
    return Erc1271PolicyId.unwrap(id1) != Erc1271PolicyId.unwrap(id2);
}

// ConfigId
using { configIdEq as == } for ConfigId global;
using { configIdNeq as != } for ConfigId global;

function configIdEq(ConfigId id1, ConfigId id2) pure returns (bool) {
    return ConfigId.unwrap(id1) == ConfigId.unwrap(id2);
}

function configIdNeq(ConfigId id1, ConfigId id2) pure returns (bool) {
    return ConfigId.unwrap(id1) != ConfigId.unwrap(id2);
}
