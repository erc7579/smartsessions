// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "../DataTypes.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import "forge-std/console2.sol";

string constant POLICY_DATA_NOTATION = "PolicyData(address policy,bytes initData)";
bytes32 constant POLICY_DATA_TYPEHASH = keccak256(abi.encodePacked(POLICY_DATA_NOTATION));
string constant ACTION_DATA_NOTATION_RAW =
    "ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)";
bytes32 constant ACTION_DATA_TYPEHASH = keccak256(abi.encodePacked(ACTION_DATA_NOTATION_RAW, POLICY_DATA_NOTATION));

string constant ERC7739_DATA_NOTATION_RAW = "ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)";
bytes32 constant ERC7739_DATA_TYPEHASH = keccak256(abi.encodePacked(ERC7739_DATA_NOTATION_RAW, POLICY_DATA_NOTATION));

string constant SESSION_NOTATION_RAW =
    "SessionEIP712(address account,address smartSession,uint8 mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[] actions)";
bytes32 constant SESSION_TYPEHASH = keccak256(
    abi.encodePacked(SESSION_NOTATION_RAW, ACTION_DATA_NOTATION_RAW, ERC7739_DATA_NOTATION_RAW, POLICY_DATA_NOTATION)
);

string constant CHAIN_TUPLE_NOTATION = "ChainSpecificEIP712(uint64 chainId,uint256 nonce)";
bytes32 constant CHAIN_TUPLE_TYPEHASH = keccak256(abi.encodePacked(CHAIN_TUPLE_NOTATION));
string constant MULTICHAIN_SESSION_NOTATION =
    "MultiChainSession(ChainSpecificEIP712[] chainSpecifics,SessionEIP712 session)";

bytes32 constant MULTICHAIN_SESSION_TYPEHASH = keccak256(
    abi.encodePacked(
        MULTICHAIN_SESSION_NOTATION,
        ACTION_DATA_NOTATION_RAW,
        CHAIN_TUPLE_NOTATION,
        ERC7739_DATA_NOTATION_RAW,
        POLICY_DATA_NOTATION,
        SESSION_NOTATION_RAW
    )
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

library HashLib {
    error ChainIdMismatch(uint64 providedChainId);
    error HashMismatch(bytes32 providedHash, bytes32 computedHash);

    using EfficientHashLib for bytes32;
    using HashLib for *;

    /**
     * Should never be used directly on-chain, only via sessionDigest()
     * Only for external use - to be able to pass smartSession when
     * testing for different chains which may have different addresses for
     * the Smart Session contract
     * It is exactly how signTypedData will hash such an object
     * when this object is an inner struct
     * It won't use eip712 domain for it as it is inner struct
     */
    function _sessionDigest(
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
                session.userOpPolicies.hashPolicyDataArray(),
                session.erc7739Policies.hashERC7739Data(),
                session.actions.hashActionDataArray()
            )
        );
    }

    function hashPolicyData(PolicyData memory policyData) internal pure returns (bytes32) {
        return keccak256(abi.encode(POLICY_DATA_TYPEHASH, policyData.policy, keccak256(policyData.initData)));
    }

    function hashPolicyDataArray(PolicyData[] memory policyDataArray) internal pure returns (bytes32) {
        uint256 length = policyDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = policyDataArray[i].hashPolicyData();
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashActionData(ActionData memory actionData) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ACTION_DATA_TYPEHASH,
                actionData.actionTargetSelector,
                actionData.actionTarget,
                hashPolicyDataArray(actionData.actionPolicies)
            )
        );
    }

    function hashActionDataArray(ActionData[] memory actionDataArray) internal pure returns (bytes32) {
        uint256 length = actionDataArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = actionDataArray[i].hashActionData();
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashERC7739Data(ERC7739Data memory erc7739Data) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                ERC7739_DATA_TYPEHASH,
                erc7739Data.allowedERC7739Content.hashStringArray(),
                erc7739Data.erc1271Policies.hashPolicyDataArray()
            )
        );
    }

    function hashStringArray(string[] memory stringArray) internal pure returns (bytes32) {
        uint256 length = stringArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = keccak256(abi.encodePacked(stringArray[i]));
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashERC7739Content(string memory content) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(content));
    }

    function hashChainSpecific(ChainSpecific memory chain) internal pure returns (bytes32) {
        return keccak256(abi.encode(CHAIN_TUPLE_TYPEHASH, chain.chainId, chain.nonce));
    }

    function hashChainSpecificArray(ChainSpecific[] memory chains) internal pure returns (bytes32) {
        uint256 length = chains.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = hashChainSpecific(chains[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashMultiChainSession(
        EnableSession memory enableData,
        address account,
        SmartSessionMode mode,
        uint256 nonce,
        address smartSessions
    )
        internal
        pure
        returns (bytes32 digest)
    {
        console2.log("hashMultiChainSession");
        console2.log("nonce", nonce);
        // derive EIP712 digest of the enable data and ALL the chains where this session is valid
        digest = keccak256(
            abi.encode(
                MULTICHAIN_SESSION_TYPEHASH,
                hashChainSpecificArray(enableData.chains),
                _sessionDigest(enableData.sessionToEnable, account, address(smartSessions), mode)
            )
        );
    }

    function getEnableDigest(
        EnableSession memory enableData,
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

        digest = hashMultiChainSession(enableData, account, mode, nonce, address(this));
    }
}
