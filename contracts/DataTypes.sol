import "./lib/ArrayMap4337Lib.sol";

type SignerId is bytes32;

type ActionId is bytes32;

type ActionPolicyId is bytes32;

type SignedActionId is bytes32;

function toActionPolicyId(SignerId signerId, ActionId actionId) pure returns (ActionPolicyId policyId) {
    policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(SignerId.unwrap(signerId), ActionId.unwrap(actionId))));
}

function toSignedActionId(SignerId signerId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", SignerId.unwrap(signerId), ActionId.unwrap(actionId)))
    );
}

type PermissionDescriptor is bytes4;

uint256 constant _SIGNER_VALIDATORS_SLOT_SEED = 0x5a8d4c29;
uint256 constant _RENOUNCED_PERMISSIONS_SLOT_SEED = 0xa8cc43e2;
uint256 constant _NONCES_SLOT_SEED = 0xfcc720b6;

enum PermissionManagerMode {
    USE,
    ENABLE,
    UNSAFE_ENABLE
}
