import "./DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as Bytes32Vec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/lib/ArrayMap4337Lib.sol";

import "./interfaces/ISigner.sol";

abstract contract PermissionManagerBase {
    mapping(SignerId => AddressVec) internal $userOpPolicies;
    mapping(ActionId => mapping(SignerId => AddressVec)) internal $actionPolicies;
    mapping(SignerId => AddressVec) internal $erc1271Policies;
    mapping(SignerId => Bytes32Vec) internal $enabledSignerIds;
    mapping(SignerId => Bytes32Vec) internal $enabledActionIds;
    mapping(SignerId => mapping(address smartAccount => ISigner)) internal $isigners;

    function setUserOpPolicy(SignerId signerId) public { }
    function setActionPolicy(SignerId signerId, ActionId actionId) public { }
    function setERC1271Policy(SignerId signerId) public { }
}
