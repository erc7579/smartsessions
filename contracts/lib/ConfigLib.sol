import "../DataTypes.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "./ArrayMap4337Lib.sol";

library ConfigLib {
    function enable(
        mapping(SignerId => BytesVec) storage self,
        SignerId signerId,
        address isigner,
        address smartAccount,
        bytes calldata signerData
    )
        internal
    { }

    function enablePolicy(
        mapping(SignerId => AddressVec) storage $policy,
        SignerId signerId,
        address account,
        bytes calldata policy
    )
        internal
    { }
}
