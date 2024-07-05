// SPDX-License-Identifier: MIT

pragma solidity ^0.8.23;

// import { ISignerValidator } from "contracts/interfaces/ISignerValidator.sol";
import { ECDSA } from "solady/utils/ECDSA.sol";
import "./passkey.sol";
import "forge-std/console2.sol";
// import "./passkey.sol";

// removing trusted forwarder dependency here as it is only required during onInstall/onUninstall
// and not during usage (checkSignature)
// import { TrustedForwarderWithId } from "contracts/utils/TrustedForwarders.sol";

struct Config {
    address eoaSigner;
    WebAuthnValidatorData passkeySigner;
}

contract WCSigner   /*, TrustedForwarderWithId*/ {
    using PasskeyHelper for *;

    error InvalidPublicKey();

    mapping(address => uint256) public usedIds;
    mapping(bytes32 signerId => mapping(address smartAccount => Config)) public signer;

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
        returns (bytes4)
    {
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(hash);
        (bytes memory sig1, bytes memory sig2) = abi.decode(sig, (bytes, bytes));

        Config storage config = signer[signerId][sender];

        // recover ecdsa to eoa signer;
        address recovered = ECDSA.recover(ethHash, sig1);

        bool eoaValid = recovered == config.eoaSigner;

        console2.log(config.passkeySigner.pubKeyX, config.passkeySigner.pubKeyY);
        bool passkeyValid = config.passkeySigner.verifyPasskey(ethHash, sig2);
        console2.log(eoaValid, passkeyValid);


        if (eoaValid && passkeyValid) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    // function _onInstallPasskey(bytes32 signerId, WebAuthnValidatorData memory data) internal {
    //     if (data.pubKeyX == 0 || data.pubKeyY == 0) {
    //         revert InvalidPublicKey();
    //     }
    //     Config storage config = signer[signerId][msg.sender];
    //
    //     config.passkeySigner = data;
    // }

    function isInitialized(address smartAccount) external view returns (bool) {
        return usedIds[smartAccount] > 0;
    }

    function onInstall(bytes calldata data) external {
        bytes32 signerId = bytes32(data[:32]);
        (address eoa, WebAuthnValidatorData memory signer2) = abi.decode(data[32:], (address, WebAuthnValidatorData));
        Config storage config = signer[signerId][msg.sender];
        config.passkeySigner = signer2;
        config.eoaSigner = eoa;

        usedIds[msg.sender]++;
    }

    function onUninstall(bytes calldata data) external { }

    function isModuleType(uint256 id) external pure returns (bool) {
        return id == 111;
    }

    function supportsInterface(bytes4) external view returns (bool) {
        return false;
    }
}
