// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

// import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import "./passkey.sol";
import "forge-std/console2.sol";
import "contracts/interfaces/ISigner.sol";
import { SubLib }  from "contracts/lib/SubLib.sol";
// import "./passkey.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

struct Config {
    address eoaSigner;
    WebAuthnValidatorData passkeySigner;
}

contract WCSigner is ISigner /*, TrustedForwarderWithId*/ {
    using PasskeyHelper for *;
    using SubLib for bytes;

    error InvalidPublicKey();

    mapping(address msgSender => mapping(address opSender => uint256)) public usedIds;
    mapping(SessionId sessionId => mapping(address multiplexer => mapping(address smartAccount => Config))) public
        signer;

    // can use sender as argument here as the method is view
    // so even external calls with arbitrary sender can not break things
    function checkSignature(
        SessionId signerId,
        address sender,
        bytes32 hash,
        bytes calldata sig
    )
        external
        view
        returns (bytes4)
    {
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        (bytes memory sig1, bytes memory sig2) = abi.decode(sig, (bytes, bytes));

        Config storage config = signer[signerId][msg.sender][sender];

        // recover ecdsa to eoa signer;
        address recovered = ECDSA.recover(ethHash, sig1);

        bool eoaValid = recovered == config.eoaSigner;
        console2.log("eoavalid", eoaValid);

        console2.log(config.passkeySigner.pubKeyX, config.passkeySigner.pubKeyY);
        bool passkeyValid = config.passkeySigner.verifyPasskey(ethHash, sig2);
        console2.log(eoaValid, passkeyValid);

        if (eoaValid && passkeyValid) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    function isInitialized(address account) external view returns (bool) {
        return usedIds[msg.sender][account] > 0;
    }

    function isInitialized(address account, SessionId id) external view returns (bool) {
        return signer[id][msg.sender][account].eoaSigner != address(0);
    }

    function isInitialized(address multiplexer, address account) external view returns (bool) {
        return usedIds[multiplexer][account] > 0;
    }

    function isInitialized(address multiplexer, address account, SessionId id) external view returns (bool) {
        return signer[id][multiplexer][account].eoaSigner != address(0);
    }

    function onInstall(bytes calldata data) external {
        (SessionId id, address opSender, bytes calldata _data) = data.parseInstallData();
        _initForAccount(opSender, id, _data);
        // bytes32 signerId = bytes32(data[:32]);
        // (address eoa, WebAuthnValidatorData memory signer2) = abi.decode(data[32:], (address,
        // WebAuthnValidatorData));
        // Config storage config = signer[signerId][msg.sender];
        // config.passkeySigner = signer2;
        // config.eoaSigner = eoa;
        //
        // usedIds[msg.sender]++;
    }

    function _initForAccount(address account, SessionId id, bytes calldata initData) internal {
        console2.log("initForAccount");

(address eoa, WebAuthnValidatorData memory signer2) = abi.decode(initData, (address, WebAuthnValidatorData));
        console2.log(eoa, signer2.pubKeyX, signer2.pubKeyY);
        Config storage config = signer[id][msg.sender][account];
        config.passkeySigner = signer2;
        config.eoaSigner = eoa;
        console2.log(signer[id][msg.sender][account].eoaSigner);

        usedIds[msg.sender][account]++;
    }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }

    function supportsInterface(bytes4 sig) external view returns (bool) {
        return sig == type(ISigner).interfaceId;
    }

    function _deinitForAccount(address account, SessionId id) internal { }

    function checkUserOpSignature(
        bytes32 id,
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    )
        external
        payable
        returns (uint256)
    {
        return 1;
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

        (address eoa, WebAuthnValidatorData memory passkey) = abi.decode(data, (address, WebAuthnValidatorData));

        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        (bytes memory sig1, bytes memory sig2) = abi.decode(sig, (bytes, bytes));

        // recover ecdsa to eoa signer;
        address recovered = ECDSA.recover(ethHash, sig1);
        bool eoaValid = recovered == eoa;
        bool passkeyValid = passkey.verifyPasskey(ethHash, sig2);

        if (eoaValid && passkeyValid) {
            return true;
        }
        
    }
}
