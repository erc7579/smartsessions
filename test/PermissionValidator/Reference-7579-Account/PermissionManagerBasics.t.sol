// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR } from "modulekit/external/ERC7579.sol";
import { PermissionManager } from "contracts/validators/PermissionManager.sol";
import { SimpleSigner } from "contracts/test/mocks/SimpleSigner.sol";
import { UsageLimitPolicy } from "contracts/test/mocks/UsageLimitPolicy.sol";
import { SimpleGasPolicy } from "contracts/test/mocks/SimpleGasPolicy.sol";

import "forge-std/console2.sol";

contract PermissionManagerBaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;

    // account and modules
    AccountInstance internal instance;
    PermissionManager internal permissionManager;
    
    bytes32 signerId;

    SimpleSigner internal simpleSignerValidator;
    address sessionSigner1;
    uint256 sessionSigner1Pk;

    UsageLimitPolicy internal usageLimitPolicy;
    SimpleGasPolicy internal simpleGasPolicy;

    function setUp() public {
        init();

        // Create the validator
        permissionManager = new PermissionManager();
        vm.label(address(permissionManager), "PermissionManager");

        // Create the signer validator
        simpleSignerValidator = new SimpleSigner();
        vm.label(address(simpleSignerValidator), "SimpleSignerValidator");

        // Deploy Policies
        usageLimitPolicy = new UsageLimitPolicy();
        vm.label(address(usageLimitPolicy), "UsageLimitPolicy");
        simpleGasPolicy = new SimpleGasPolicy();
        vm.label(address(simpleGasPolicy), "SimpleGasPolicy");

        // Create the account and install PermissionManager as a validator and as an executor
        instance = makeAccountInstance("PermissionManager");
        vm.deal(address(instance.account), 10 ether);

        (sessionSigner1, sessionSigner1Pk) = makeAddrAndKey("sessionSigner1");

        //example signerId
        signerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp));

        instance.installModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: address(permissionManager),
            data: abi.encodePacked(bytes1(uint8(MODULE_TYPE_EXECUTOR)))
        });

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(permissionManager),
            data: abi.encodePacked(
                uint8(MODULE_TYPE_VALIDATOR), //1 byte
                signerId, 
                // data for setting up the signer
                simpleSignerValidator, 
                sessionSigner1,
                // data for setting up the userOp Policies
                uint8(0x02), // number of policies
                address(usageLimitPolicy),
                uint256(10), // limit
                address(simpleGasPolicy), 
                uint256(2**256-1) // limit
            )
        });

        assertTrue(simpleSignerValidator.isInitialized(instance.account));
        assertTrue(usageLimitPolicy.isInitialized(instance.account));
        assertTrue(simpleGasPolicy.isInitialized(instance.account));
        
    }

    function testExec() public {
        // Create a target address and send some ether to it
        address target = makeAddr("target");
        uint256 value = 1 ether;
        console2.log("target ", target);

        // Get the current balance of the target
        uint256 prevBalance = target.balance;

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            target: target,
            value: value,
            callData: "0xdeaf",
            txValidator: address(permissionManager)
        });

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner1Pk, userOpData.userOpHash);

        // Set the signature
        bytes memory signature = abi.encodePacked(
            bytes1(0x00), //not enable mode
            signerId,
            r,s,v
        );
        userOpData.userOp.signature = signature;
        
        // Execute the UserOp
        userOpData.execUserOps();

        // Check if the balance of the target has NOT increased
        assertEq(target.balance, prevBalance+value, "Balance not increased");
    }
}

/*
0x
0000000000000000000000000000000000000000000000000000000000000040
000000000000000000000000000000000000000000000000000000000000003c   0x3c = 60
2d1d989af240b673c84ceeb3e6279ea98a2cfd05
0000000000000000000000000000000000000000000000000de0b6b3a7640000
313231323132313200000000

*/