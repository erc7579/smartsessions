import "../DataTypes.sol";
import { PackedUserOperation } from "modulekit/external/ERC4337.sol";
import {
    AddressArrayMap4337 as AddressVec,
    Bytes32ArrayMap4337 as BytesVec,
    ArrayMap4337Lib as AddressVecLib
} from "contracts/utils/lib/ArrayMap4337Lib.sol";

import { ERC7579ValidatorBase } from "modulekit/Modules.sol";
import { ValidationDataLib } from "contracts/utils/lib/ValidationDataLib.sol";

import "./TrustedForwardLib.sol";

library PolicyLib {
    using PolicyLib for *;
    using AddressVecLib for *;
    using TrustedForwardLib for address;
    using ValidationDataLib for ERC7579ValidatorBase.ValidationData;

    error PolicyAlreadyUsed(address policy);

    function check(
        mapping(SignerId => AddressVec) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signer,
        bytes memory callData
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {
        address account = userOp.sender;
        AddressVec storage $addresses = $policies[signer];

        uint256 length = $addresses.length(account);

        for (uint256 i; i < length; i++) {
            address policy = $addresses.get(account, i);
            uint256 validationDataFromPolicy =
                uint256(bytes32(policy.fwdCall({ forAccount: account, callData: callData })));
            vd = vd.intersectValidationData(ERC7579ValidatorBase.ValidationData.wrap(validationDataFromPolicy));
        }
    }


    function checkAction(
        mapping(SignerId => AddressVec) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signer,
        bytes memory callData
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    {

        ActionId actionId =
            ActionId.wrap(keccak256(abi.encodePacked(target, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0))));

        vd = $policies.check(signer, callData);
    }

    function checkExectution(
        mapping(SignerId => AddressVec) storage $policies,
        PackedUserOperation calldata userOp,
        SignerId signer
    )
        internal
        returns (ERC7579ValidatorBase.ValidationData vd)
    { }

    // function addPolicy(AddressArrayMap4337 storage $policy, address smartAccount, address policy) internal {
    //     if (!$policy.contains(smartAccount, policy)) {
    //         $policy.push(smartAccount, policy);
    //     } else {
    //         revert PolicyAlreadyUsed(policy);
    //     }
    // }
    //
    // function enableUserOpPolicy(
    //     SignerId signerId,
    //     PermissionDescriptor permissionDescriptor,
    //     bytes calldata permissionData
    // )
    //     internal
    //     returns (uint256 addOffset)
    // {
    //     uint256 numberOfPolicies = permissionDescriptor.getUserOpPoliciesNumber();
    //     for (uint256 i; i < numberOfPolicies; i++) {
    //         (address userOpPolicy, bytes calldata policyData) = parsePolicy(permissionData[addOffset:]);
    //         addOffset += 24 + policyData.length;
    //
    //         AddressArrayMap4337 storage policies = userOpPolicies[signerId];
    //         addPolicy(policies, smartAccount, userOpPolicy);
    //
    //         bytes memory _data = abi.encodePacked(signerId, policyData);
    //         _initSubmodule(userOpPolicy, SignerId.unwrap(signerId), smartAccount, _data);
    //     }
    // }
    //
    // function enableActionPolicy(
    //     SignerId signerId,
    //     PermissionDescriptor permissionDescriptor,
    //     bytes calldata permissionData
    // )
    //     internal
    //     returns (uint256)
    // {
    //     uint256 numberOfPolicies = permissionDescriptor.getActionPoliciesNumber();
    //     ActionId actionId = ActionId.wrap(bytes32(permissionData[0:32]));
    //     uint256 addOffset = 32;
    //     if (numberOfPolicies != 0) {
    //         Bytes32ArrayMap4337 storage actionIds = enabledActionIds[signerId];
    //         if (!actionIds.contains(msg.sender, ActionId.unwrap(actionId))) {
    //             actionIds.push(msg.sender, ActionId.unwrap(actionId));
    //         }
    //     }
    //     for (uint256 i; i < numberOfPolicies; i++) {
    //         (address actionPolicy, bytes calldata policyData) = parsePolicy(permissionData[addOffset:]);
    //         addOffset += 24 + policyData.length;
    //         _enableActionPolicy(signerId, actionId, actionPolicy, msg.sender, policyData);
    //     }
    //     return addOffset;
    // }
    //
    // function enableERC1271Policy(
    //     SignerId signerId,
    //     PermissionDescriptor permissionDescriptor,
    //     bytes calldata permissionData
    // )
    //     internal
    //     returns (uint256 addOffset)
    // {
    //     uint256 numberOfPolicies = permissionDescriptor.get1271PoliciesNumber();
    //     for (uint256 i; i < numberOfPolicies; i++) {
    //         (address erc1271Policy, bytes calldata policyData) = parsePolicy(permissionData[addOffset:]);
    //         addOffset += 24 + policyData.length;
    //         _enableERC1271Policy(signerId, erc1271Policy, msg.sender, policyData);
    //     }
    // }
    //
    // function parsePolicy(bytes calldata partialPermissionData)
    //     internal
    //     pure
    //     returns (address policy, bytes calldata policyData)
    // {
    //     policy = address(uint160(bytes20(partialPermissionData[0:20])));
    //     uint256 dataLength = uint256(uint32(bytes4(partialPermissionData[20:24])));
    //     policyData = partialPermissionData[24:24 + dataLength];
    // }
    //
    // function isSignerEnableMode(PermissionDescriptor descr) internal pure returns (bool) {
    //     return ((PermissionDescriptor.unwrap(descr)) >> 24) == 0x00000001;
    // }
    //
    // function getUserOpPoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
    //     return uint256(uint32((PermissionDescriptor.unwrap(descr) & 0x00ff0000) >> 16));
    // }
    //
    // function getActionPoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
    //     return uint256(uint32((PermissionDescriptor.unwrap(descr) & 0x0000ff00) >> 8));
    // }
    //
    // function get1271PoliciesNumber(PermissionDescriptor descr) internal pure returns (uint256) {
    //     return uint256(uint32(PermissionDescriptor.unwrap(descr) & 0x000000ff));
    // }
}
