// spdx-license-identifier: agpl-3.0-only
pragma solidity ^0.8.25;

import "@rhinestone/deploy-sol/src/DeployModule.sol";
import { Script } from "forge-std/Script.sol";
import { SmartSession } from "contracts/SmartSession.sol";
import "forge-std/console2.sol";

contract DeploySmartSession is Script {
    function deploy(uint256 pKey) public {
        // bytes32 smartSessionSalt = 0x000000000000000000000000000000000000000014e7155016040b01c80e1684;
        // bytes memory bytecode = vm.getCode("./deployArtifacts/SmartSession/SmartSession/SmartSession.json");
        // address smartSession = ModuleDeployer.broadcastDeploy(pKey, bytecode, smartSessionSalt);
        // console2.log("SmartSession Addr: ", smartSession);
        //
        // bytes32 erc20SpendingLimitSalt = 0x0000000000000000000000000000000000000000d3d48fca7688b88b32020080;
        // bytecode = vm.getCode(
        //     "./deployArtifacts/ERC20SpendingLimitPolicy/ERC20SpendingLimitPolicy/ERC20SpendingLimitPolicy.json"
        // );
        // address spendingLimit = ModuleDeployer.broadcastDeploy(pKey, bytecode, erc20SpendingLimitSalt);
        // console2.log("spendingLimit Addr: ", spendingLimit);
        //
        // bytes32 sudoSalt = 0x0000000000000000000000000000000000000000d3d48fca7688b88b32020080;
        // bytecode = vm.getCode("./deployArtifacts/SudoPolicy/SudoPolicy/SudoPolicy.json");
        // address sudo = ModuleDeployer.broadcastDeploy(pKey, bytecode, sudoSalt);
        // console2.log("sudoPolicy Addr: ", sudo);
        //
        // bytes32 uniActionSalt = 0x0000000000000000000000000000000000000000d3d48fca7688b88b32020080;
        // bytecode = vm.getCode("./deployArtifacts/UniActionPolicy/UniActionPolicy/UniActionPolicy.json");
        // address uniAction = ModuleDeployer.broadcastDeploy(pKey, bytecode, uniActionSalt);
        // console2.log("uniAction Addr: ", uniAction);

        bytes32 fallbackSalt = 0x0000000000000000000000000000000000000000d3d48fca7688b88b32020080;
        bytes memory bytecode = vm.getCode("./artifacts/SmartSessionCompatibilityFallback/SmartSessionCompatibilityFallback.json");
        address uniAction = ModuleDeployer.broadcastDeploy(pKey, bytecode, fallbackSalt);
        console2.log("uniAction Addr: ", uniAction);
    }
}
