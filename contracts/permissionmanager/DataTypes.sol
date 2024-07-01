import "../utils/lib/ArrayMap4337Lib.sol";

type SignerId is bytes32;

type ActionId is bytes32;

type PermissionDescriptor is bytes4;

uint256 constant _SIGNER_VALIDATORS_SLOT_SEED = 0x5a8d4c29;
uint256 constant _RENOUNCED_PERMISSIONS_SLOT_SEED = 0xa8cc43e2;
uint256 constant _NONCES_SLOT_SEED = 0xfcc720b6;

enum Mode {
    USE,
    ENABLE
}

struct SignerIDConfig {
    mapping(ActionId => AddressArrayMap4337) actionPolicies;
    AddressArrayMap4337 userOpPolicies;
    AddressArrayMap4337 erc1271Policies;
    Bytes32ArrayMap4337 enabledActionIds;
    Bytes32ArrayMap4337 enabledSignerIds;
}
