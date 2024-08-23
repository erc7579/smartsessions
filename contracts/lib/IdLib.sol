// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";

library IdLib {
    function toPermissionId(
        address account,
        ISessionValidator sessionValidator
    )
        internal
        view
        returns (PermissionId permissionId)
    {
        permissionId = PermissionId.wrap(
            keccak256(abi.encodePacked("Signer Id for ", account, address(sessionValidator), block.timestamp))
        );
    }

    function toUserOpPolicyId(PermissionId permissionId) internal view returns (UserOpPolicyId userOpPolicyId) {
        userOpPolicyId = UserOpPolicyId.wrap(PermissionId.unwrap(permissionId));
    }

    function toActionId(address target, bytes4 functionSelector) internal pure returns (ActionId actionId) {
        actionId = ActionId.wrap(keccak256(abi.encodePacked(target, functionSelector)));
    }

    function toActionPolicyId(
        PermissionId permissionId,
        ActionId actionId
    )
        internal
        pure
        returns (ActionPolicyId policyId)
    {
        policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(permissionId, actionId)));
    }

    function toErc1271PolicyId(PermissionId permissionId) internal view returns (Erc1271PolicyId erc1271PolicyId) {
        erc1271PolicyId = Erc1271PolicyId.wrap(keccak256(abi.encodePacked("ERC1271: ", permissionId)));
    }

    /* function toSignedActionId(PermissionId permissionId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", PermissionId.unwrap(permissionId), ActionId.unwrap(actionId)))
    );
    } */

    function toConfigId(PermissionId permissionId, address account) internal view returns (ConfigId _id) {
        _id = ConfigId.wrap(keccak256(abi.encodePacked(account, permissionId)));
    }

    function toConfigId(UserOpPolicyId userOpPolicyId, address account) internal view returns (ConfigId _id) {
        _id = ConfigId.wrap(keccak256(abi.encodePacked(account, userOpPolicyId)));
    }

    function toConfigId(ActionPolicyId actionPolicyId, address account) internal view returns (ConfigId _id) {
        _id = ConfigId.wrap(keccak256(abi.encodePacked(account, actionPolicyId)));
    }

    function toConfigId(
        PermissionId permissionId,
        ActionId actionId,
        address account
    )
        internal
        view
        returns (ConfigId _id)
    {
        _id = toConfigId(toActionPolicyId(permissionId, actionId), account);
    }

    function toConfigId(Erc1271PolicyId erc1271PolicyId, address account) internal view returns (ConfigId _id) {
        _id = ConfigId.wrap(keccak256(abi.encodePacked(account, erc1271PolicyId)));
    }

    function toConfigId(PermissionId permissionId) internal view returns (ConfigId _id) {
        _id = toConfigId(permissionId, msg.sender);
    }

    function toConfigId(UserOpPolicyId userOpPolicyId) internal view returns (ConfigId _id) {
        _id = toConfigId(userOpPolicyId, msg.sender);
    }

    function toConfigId(ActionPolicyId actionPolicyId) internal view returns (ConfigId _id) {
        _id = toConfigId(actionPolicyId, msg.sender);
    }

    function toConfigId(PermissionId permissionId, ActionId actionId) internal view returns (ConfigId _id) {
        _id = toConfigId(toActionPolicyId(permissionId, actionId));
    }

    function toConfigId(Erc1271PolicyId erc1271PolicyId) internal view returns (ConfigId _id) {
        _id = toConfigId(erc1271PolicyId, msg.sender);
    }
}
