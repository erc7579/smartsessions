// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "contracts/DataTypes.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "contracts/lib/HashLib.sol";

library TestHashLib {
    using TestHashLib for *;
    using HashLib for *;

    /**
     * This function is for testing purposes.
     * It is never used inside the SmartSession as SmartSession never has all the sessions
     * It requires accounts, smart sessions, modes and nonces from outside as they are
     * from other chains
     */
    function multichainDigest(
        MultiChainSession memory multichainSession,
        address[] memory accounts,
        address[] memory smartSessions,
        SmartSessionMode[] memory modes,
        uint256[] memory nonces
    )
        internal
        pure
        returns (bytes32)
    {
        // make hash from the full sessions => should return same hash as signTypedData()
        // and should return same hash as multichainDigest(ChainDigest[])

        // multichainSession.sessionsAndChainIds
        bytes32 structHash = keccak256(
            abi.encode(
                MULTICHAIN_SESSION_TYPEHASH,
                multichainSession.sessionsAndChainIds.hashChainSessionArray(modes, nonces, accounts, smartSessions)
            )
        );
        return MessageHashUtils.toTypedDataHash(_MULTICHAIN_DOMAIN_SEPARATOR, structHash);
    }

    function hashChainSessionArray(
        ChainSession[] memory chainSessionArray,
        SmartSessionMode[] memory modes,
        uint256[] memory nonces,
        address[] memory accounts,
        address[] memory smartSessions
    )
        internal
        pure
        returns (bytes32)
    {
        uint256 length = chainSessionArray.length;
        bytes32[] memory hashes = new bytes32[](length);
        for (uint256 i; i < length; i++) {
            hashes[i] = chainSessionArray[i].hashChainSession(modes[i], nonces[i], accounts[i], smartSessions[i]);
        }
        return keccak256(abi.encodePacked(hashes));
    }

    function hashChainSession(
        ChainSession memory chainSession,
        SmartSessionMode mode,
        uint256 nonce,
        address account,
        address smartSession
    )
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CHAIN_SESSION_TYPEHASH,
                chainSession.chainId,
                chainSession.session._sessionDigest(account, smartSession, mode, nonce)
            )
        );
    }
}
