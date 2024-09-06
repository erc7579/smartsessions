// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

string constant POLICY_DATA = "PolicyData(address policy,bytes initData)";
bytes32 constant POLICY_DATA_TYPEHASH = keccak256(abi.encodePacked(POLICY_DATA));

string constant ACTION_DATA = "ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)";
bytes32 constant ACTION_DATA_TYPEHASH = keccak256(abi.encodePacked(ACTION_DATA, POLICY_DATA));

string constant ERC7739_DATA = "ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)";
bytes32 constant ERC7739_DATA_TYPEHASH = keccak256(abi.encodePacked(ERC7739_DATA, POLICY_DATA));

string constant SESSION_DATA =
    "SessionEIP712(address account,address smartSession,uint8 mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)";
bytes32 constant SESSION_TYPEHASH = keccak256(abi.encodePacked(SESSION_DATA, ACTION_DATA, ERC7739_DATA, POLICY_DATA));

string constant CHAIN_EIP712_TUPLE = "ChainSpecificEIP712(uint64 chainId,uint256 nonce)";
bytes32 constant CHAIN_TUPLE_TYPEHASH = keccak256(abi.encodePacked(CHAIN_EIP712_TUPLE));
string constant MULTI_CHAIN_SESSION =
    "MultiChainSession(bytes32 permissionId,ChainSpecificEIP712[] chainSpecifics,SessionEIP712 session)";

bytes32 constant MULTICHAIN_SESSION_TYPEHASH = keccak256(
    abi.encodePacked(MULTI_CHAIN_SESSION, ACTION_DATA, CHAIN_EIP712_TUPLE, ERC7739_DATA, POLICY_DATA, SESSION_DATA)
);

/// @dev `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
bytes32 constant _DOMAIN_TYPEHASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

// keccak256(abi.encode(_DOMAIN_TYPEHASH, keccak256("SmartSession"), keccak256(""), 0, address(0)));
// One should use the same domain separator where possible
// or provide the following EIP712Domain struct to the signTypedData() function
// Name: "SmartSession" (string)
// Version: "" (string)
// ChainId: 0 (uint256)
// VerifyingContract: address(0) (address)
// it is introduced for compatibility with signTypedData()
// all the critical data such as chainId and verifyingContract are included
// in session hashes
// https://docs.metamask.io/wallet/reference/eth_signtypeddata_v4
bytes32 constant _DOMAIN_SEPARATOR = 0xa82dd76056d04dc31e30c73f86aa4966336112e8b5e9924bb194526b08c250c1;
/**
 *
 * +------------------------+
 * | MultiChainSession      |
 * +------------------------+
 * | bytes32 permissionId   |        one MultiChainSession can be valid on multiple chains
 * | ChainSpecificEIP712[]  |--------------------------------------+------------------------+
 * | SessionEIP712          |--+                                   | ChainSpecificEIP712    |
 * +------------------------+  |                                   +------------------------+
 *                             |                                   | uint64 chainId         |
 *   +-------------------------+                                   | uint256 nonce          |
 *   |                                                             +------------------------+
 *   v
 * +------------------------+
 * | SessionEIP712          |
 * +------------------------+
 * | address account         |
 * | address smartSession    |
 * | uint8 mode              |
 * | address sessionValidator|
 * | bytes32 salt            |
 * | bytes initData          |
 * | PolicyData[] userOp     |--------------------------------------+------------------------+
 * | ERC7739Data             |---------+                            | PolicyData             |
 * | ActionData[]            |--+      |                            +------------------------+
 * +------------------------+   |      |                            | address policy         |
 *                              |      |                            | bytes initData         |
 *   +-------------------------+       |                            +------------------------+
 *   |                                 |                              ^
 *   v                                 |                              |
 * +------------------------+          |                              |
 * | ActionData             |          |                              |
 * +------------------------+          |                              |
 * | bytes4 selector        |          |                              |
 * | address target         |          |                              |
 * | PolicyData[]           |-----------------------------------------+
 * +------------------------+          |                              |
 *                                     |                              |
 *   +------------------------------- +                               |
 *   |                                                                |
 *   v                                                                |
 * +------------------------+                                         |
 * | ERC7739Data            |                                         |
 * +------------------------+                                         |
 * | string[] allowed       |                                         |
 * | PolicyData[]           |-----------------------------------------+
 * +------------------------+
 */

library HashLib {
    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    using EfficientHashLib for *;
    using HashLib for *;
    using TypeHashLib for *;

    function hash(
        EnableSession memory enableData,
        PermissionId permissionId,
        address account,
        SmartSessionMode mode,
        address smartSession
    )
        internal
        pure
        returns (bytes32 digest)
    {
        bytes32[] memory a = EfficientHashLib.malloc(4);
        a.set(0, MULTICHAIN_SESSION_TYPEHASH);
        a.set(1, PermissionId.unwrap(permissionId));
        a.set(2, enableData.chains.hash());
        a.set(3, enableData.sessionToEnable.hash(account, smartSession, mode));
        digest = a.hash();
    }

    function getEnableDigest(
        EnableSession memory enableData,
        PermissionId permissionId,
        address account,
        uint256 nonce,
        SmartSessionMode mode
    )
        internal
        view
        returns (bytes32 digest)
    {
        // ensure that the current chainid is part of the digest
        if (block.chainid != enableData.chains[enableData.chainDigestIndex].chainId) {
            revert ChainIdMismatch(uint64(block.chainid));
        }

        // ensure that the nonce for this chainId is the current nonce
        if (nonce != enableData.chains[enableData.chainDigestIndex].nonce) {
            revert ChainIdMismatch(uint64(block.chainid));
        }

        digest =
            enableData.hash({ permissionId: permissionId, account: account, mode: mode, smartSession: address(this) });
    }
}

library TypeHashLib {
    using TypeHashLib for *;
    using EfficientHashLib for *;

    function hash(
        Session memory session,
        address account,
        address smartSession, // for testing purposes
        SmartSessionMode mode
    )
        internal
        pure
        returns (bytes32 _hash)
    {
        // chainId is not needed as it is in the ChainSession
        _hash = keccak256(
            abi.encode(
                SESSION_TYPEHASH,
                account,
                smartSession,
                uint8(mode), // Include mode as uint8
                address(session.sessionValidator),
                session.salt,
                keccak256(session.sessionValidatorInitData),
                session.userOpPolicies.hash(),
                session.erc7739Policies.hash(),
                session.actions.hash()
            )
        );
    }

    function hash(PolicyData memory policyData) internal pure returns (bytes32 _hash) {
        return keccak256(abi.encode(POLICY_DATA_TYPEHASH, policyData.policy, keccak256(policyData.initData)));
    }

    function hash(PolicyData[] memory policyDataArray) internal pure returns (bytes32) {
        uint256 length = policyDataArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, policyDataArray[i].hash());
        }
        return a.hash();
    }

    function hash(ActionData memory actionData) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACTION_DATA_TYPEHASH,
                actionData.actionTargetSelector,
                actionData.actionTarget,
                actionData.actionPolicies.hash()
            )
        );
    }

    function hash(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, actionDataArray[i].hash());
        }
        return a.hash();
    }

    function hash(ERC7739Data memory erc7739Data) internal pure returns (bytes32 _hash) {
        bytes32[] memory a = EfficientHashLib.malloc(3);
        a.set(0, ERC7739_DATA_TYPEHASH);
        a.set(1, erc7739Data.allowedERC7739Content.hash());
        a.set(2, erc7739Data.erc1271Policies.hash());
        _hash = a.hash();
    }

    function hash(string[] memory stringArray) internal pure returns (bytes32 _hash) {
        uint256 length = stringArray.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, keccak256(abi.encodePacked(stringArray[i])));
        }
        _hash = a.hash();
    }

    function hash(string memory content) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(content));
    }

    function hash(ChainSpecific memory chain) internal pure returns (bytes32) {
        return keccak256(abi.encode(CHAIN_TUPLE_TYPEHASH, chain.chainId, chain.nonce));
    }

    function hash(ChainSpecific[] memory chains) internal pure returns (bytes32 _hash) {
        uint256 length = chains.length;
        bytes32[] memory a = EfficientHashLib.malloc(length);
        for (uint256 i; i < length; i++) {
            a.set(i, chains[i].hash());
        }
        _hash = a.hash();
    }
}
