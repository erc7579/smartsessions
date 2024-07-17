// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";

library IdLib {
    function toSignerId(address account, ISigner isigner) internal view returns (SignerId signerId) {
        signerId =
            SignerId.wrap(keccak256(abi.encodePacked("Signer Id for ", account, address(isigner), block.timestamp)));
    }

    function toUserOpPolicyId(SignerId signerId) internal view returns (UserOpPolicyId userOpPolicyId) {
        userOpPolicyId = UserOpPolicyId.wrap(SignerId.unwrap(signerId));
    }

    function toActionId(address target, bytes calldata data) internal pure returns (ActionId actionId) {
        actionId = ActionId.wrap(keccak256(abi.encodePacked(target, data.length >= 4 ? bytes4(data[0:4]) : bytes4(0))));
    }

    function toActionPolicyId(SignerId signerId, ActionId actionId) internal pure returns (ActionPolicyId policyId) {
        policyId = ActionPolicyId.wrap(keccak256(abi.encodePacked(signerId, actionId)));
    }

    function toErc1271PolicyId(SignerId signerId) internal view returns (Erc1271PolicyId erc1271PolicyId) {
        erc1271PolicyId = Erc1271PolicyId.wrap(keccak256(abi.encodePacked("ERC1271: ", signerId)));
    }

    /* function toSignedActionId(SignerId signerId, ActionId actionId) pure returns (SignedActionId policyId) {
    policyId = SignedActionId.wrap(
        keccak256(abi.encodePacked("ERC1271: ", SignerId.unwrap(signerId), ActionId.unwrap(actionId)))
    );
    } */

    function toSessionId(SignerId signerId, address account) internal view returns (SessionId _id) {
        _id = SessionId.wrap(keccak256(abi.encodePacked(account, signerId)));
    }

    function toSessionId(UserOpPolicyId userOpPolicyId, address account) internal view returns (SessionId _id) {
        _id = SessionId.wrap(keccak256(abi.encodePacked(account, userOpPolicyId)));
    }

    function toSessionId(ActionPolicyId actionPolicyId, address account) internal view returns (SessionId _id) {
        _id = SessionId.wrap(keccak256(abi.encodePacked(account, actionPolicyId)));
    }

    function toSessionId(SignerId signerId, ActionId actionId, address account) internal view returns (SessionId _id) {
        _id = toSessionId(toActionPolicyId(signerId, actionId), account);
    }

    function toSessionId(Erc1271PolicyId erc1271PolicyId, address account) internal view returns (SessionId _id) {
        _id = SessionId.wrap(keccak256(abi.encodePacked(account, erc1271PolicyId)));
    }

    function toSessionId(SignerId signerId) internal view returns (SessionId _id) {
        _id = toSessionId(signerId, msg.sender);
    }

    function toSessionId(UserOpPolicyId userOpPolicyId) internal view returns (SessionId _id) {
        _id = toSessionId(userOpPolicyId, msg.sender);
    }

    function toSessionId(ActionPolicyId actionPolicyId) internal view returns (SessionId _id) {
        _id = toSessionId(actionPolicyId, msg.sender);
    }

    function toSessionId(SignerId signerId, ActionId actionId) internal view returns (SessionId _id) {
        _id = toSessionId(toActionPolicyId(signerId, actionId));
    }

    function toSessionId(Erc1271PolicyId erc1271PolicyId) internal view returns (SessionId _id) {
        _id = toSessionId(erc1271PolicyId, msg.sender);
    }
}
