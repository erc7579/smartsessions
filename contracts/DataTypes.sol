import "./lib/ArrayMap4337Lib.sol";
import { SentinelList4337Lib } from "sentinellist/SentinelList4337.sol";

type SignerId is bytes32;

type ActionId is bytes32;

type ActionPolicyId is bytes32;

type SignedActionId is bytes32;

type SessionId is bytes32;

function toSignerId(address account, bytes32 simpleSignerValidator) view returns (SignerId signerId) {
    signerId =
        SignerId.wrap(keccak256(abi.encodePacked("Signer Id for ", account, simpleSignerValidator, block.timestamp)));
}

function toActionPolicyId(SignerId signerId, ActionId actionId) pure returns (ActionPolicyId policyId) {
    policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(SignerId.unwrap(signerId), ActionId.unwrap(actionId))));
}

function toSignedActionId(SignerId signerId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", SignerId.unwrap(signerId), ActionId.unwrap(actionId)))
    );
}

function sessionId(SignerId signerId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, SignerId.unwrap(signerId))));
}

function sessionId(ActionPolicyId signerId) view returns (SessionId _id) {
    _id = SessionId.wrap(keccak256(abi.encodePacked(msg.sender, ActionPolicyId.unwrap(signerId))));
}

function sessionId(SignerId signerId, ActionId actionId) view returns (SessionId _id) {
    _id = sessionId(toActionPolicyId(signerId, actionId));
}

struct EnableData {
    bytes permissionEnableSig;
    ActionId actionId;
    PolicyData[] userOpPolicies;
    PolicyData[] erc1271Policies;
    PolicyData[] actionPolicies;
}

struct PolicyConfig {
    SignerId signerId;
    PolicyData[] policies;
}

struct PolicyData {
    address policy;
    bytes initData;
}

struct ActionPolicyConfig {
    ActionId actionId;
    PolicyConfig[] policyConfig;
}

type PermissionDescriptor is bytes4;

enum PermissionManagerMode {
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
