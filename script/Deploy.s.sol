// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "contracts/SmartSession.sol";
import "test/mock/YesPolicy.sol";

contract DeploySmartPermission is Script {
    function run() public {
        _deploySmartSession();
    }

    function _deploySmartSession() public returns (address) {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        console2.log("Deployer Addr: ", vm.addr(privKey));
        vm.startBroadcast(privKey);


        // Create the signer validator
        bytes memory bytecode = abi.encodePacked(vm.getCode("./out/WCSigner.sol/WCSigner.json"));

        address anotherAddress;
        address cosigner;
        assembly {
            anotherAddress := create(0, add(bytecode, 0x20), mload(bytecode))
        }
        cosigner = anotherAddress;
        console2.log("WalletConnect CoSigner Addr: ", cosigner);
        vm.label(cosigner, "WalletConnect CoSigner");



        // Deploy SmartPermission
        SmartSession smartSession = new SmartSession();
        console2.log("SmartPermission Addr: ", address(smartSession));

        YesPolicy yesPolicy = new YesPolicy();
        console2.log("YesPolicy Addr: ", address(yesPolicy));
        return address(smartSession);
    }
}
