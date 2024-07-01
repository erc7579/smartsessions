// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

contract SimpleSigner is ISignerValidator /*, TrustedForwarderWithId*/ {
    mapping(address => uint256) public usedIds;
    mapping(bytes32 signerId => mapping(address smartAccount => address)) public signer;

    // can use sender as argument here as the method is view
    // so even external calls with arbitrary sender can not break things
    function checkSignature(
        bytes32 signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        override
        returns (bytes4)
    {
        address owner = signer[signerId][sender];
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

    function _onInstallSigner(bytes32 signerId, bytes calldata _data) internal {
        address smartAccount = msg.sender; /*_getAccount(signerId)*/
        require(signer[signerId][smartAccount] == address(0));
        usedIds[smartAccount]++;
        signer[signerId][smartAccount] = address(bytes20(_data[0:20]));
    }

    function _onUninstallSigner(bytes32 signerId, bytes calldata) internal {
        address smartAccount = msg.sender; /*_getAccount(signerId)*/
        require(signer[signerId][smartAccount] != address(0));
        delete signer[signerId][smartAccount];
        usedIds[smartAccount]--;
    }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[smartAccount] > 0;
    }

    function onInstall(bytes calldata data) external {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _onInstallSigner(id, _data);
    }

    function onUninstall(bytes calldata data) external {
        bytes32 id = bytes32(data[0:32]);
        bytes calldata _data = data[32:];
        _onUninstallSigner(id, _data);
    }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }
}
