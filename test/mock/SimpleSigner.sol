// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { PackedUserOperation, SessionId, ISigner } from "contracts/interfaces/ISigner.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import { SubLib } from "contracts/lib/SubLib.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

contract SimpleSigner is ISigner {
    using SubLib for bytes;

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId id => mapping(address msgSender => mapping(address userOpSender => address))) public signer;

    // can use sender as argument here as the method is view
    // so even external calls with arbitrary sender can not break things
    function checkSignature(
        SessionId id,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        override
        returns (bytes4)
    {
        address owner = signer[id][msg.sender][sender];
        address recovered;
        recovered = ECDSA.recover(hash, sig);
        if (owner == recovered) {
            return 0x1626ba7e;
        }
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        recovered = ECDSA.recover(ethHash, sig);
        if (owner == recovered) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    function checkUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256)
    { }

    function _onInstallSigner(SessionId id, address opSender, bytes calldata _data) internal {
        require(signer[id][msg.sender][opSender] == address(0));
        usedIds[msg.sender][opSender]++;
        signer[id][msg.sender][opSender] = address(bytes20(_data[0:20]));
    }

    function _onUninstallSigner(SessionId id, address opSender, bytes calldata) internal {
        require(signer[id][msg.sender][opSender] != address(0));
        delete signer[id][msg.sender][opSender];
        usedIds[msg.sender][opSender]--;
    }

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onInstallSigner(id, opSender, _data);
    }

    function onUninstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _onUninstallSigner(id, opSender, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[msg.sender][smartAccount] > 0;
    }

    function isInitialized(address multiplexer, address smartAccount) external view returns (bool) {
        return usedIds[multiplexer][smartAccount] > 0;
    }

    function isInitialized(address account, SessionId id) external view returns (bool) {
        return signer[id][msg.sender][account] != address(0);
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view returns (bool) {
        return signer[id][multiplexer][account] != address(0);
    }

    function supportsInterface(bytes4 interfaceID) external pure override returns (bool) {
        return true;
    }

    function validateSignatureWithData(
        bytes32 hash,
        bytes calldata sig,
        bytes calldata data
    )
        external
        override
        returns (bool validSig)
    {
        return true;
    }
}
