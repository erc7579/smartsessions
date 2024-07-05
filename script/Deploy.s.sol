// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.25;

import "forge-std/Script.sol";
import "contracts/SmartSession.sol";

contract DeploySmartPermission is Script {
    function run() public {
        _deploySmartSession();
    }

    function _deploySmartSession() public returns (address) {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        console2.log("Deployer Addr: ", vm.addr(privKey));
        vm.broadcast(privKey);

        // Deploy SmartPermission
        SmartSession smartSession = new SmartSession();
        console2.log("SmartPermission Addr: ", address(smartSession));
        return address(smartSession);
    }
}
