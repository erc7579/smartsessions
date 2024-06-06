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
import { TimeFramePolicy } from "contracts/test/mocks/TimeFramePolicy.sol";
import { Counter } from "contracts/test/Counter.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";

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
    TimeFramePolicy internal timeFramePolicy;

    Counter counterContract;

    function setUp() public {
        init();

        // Create the counter contract
        counterContract = new Counter();

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
        timeFramePolicy = new TimeFramePolicy();
        vm.label(address(timeFramePolicy), "TimeFramePolicy");

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

        // Signer and userOpPolicies
        bytes memory validatorInstallData = abi.encodePacked(
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
            );

        // action policies
        validatorInstallData = abi.encodePacked(
            validatorInstallData,
                uint8(0x02), // number of policies
                keccak256(abi.encodePacked(address(counterContract), counterContract.incr.selector)),//action Id
                address(usageLimitPolicy),
                uint256(2), // limit
                address(timeFramePolicy),
                uint256(((block.timestamp + 1000) << 128) + (block.timestamp ))
        );

        // 1271 policies
        validatorInstallData = abi.encodePacked(
            validatorInstallData,
                uint8(0x01), // number of policies
                address(timeFramePolicy),
                uint256(((block.timestamp + 11111) << 128) + (block.timestamp + 500))
        );

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(permissionManager),
            data: validatorInstallData
        });

        assertTrue(simpleSignerValidator.isInitialized(instance.account));
        assertTrue(usageLimitPolicy.isInitialized(instance.account));
        assertTrue(simpleGasPolicy.isInitialized(instance.account));
        
    }

    function testExec() public {
        // Create a target address and send some ether to it
        //address target = makeAddr("target");
        uint256 value = 1 ether;

        // Get the current balance of the target
        uint256 prevBalance = address(counterContract).balance;

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            target: address(counterContract),
            value: value,
            callData: abi.encodeWithSelector(counterContract.incr.selector),
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
        assertEq(address(counterContract).balance, prevBalance+value, "Balance not increased");
    }

    function test1271SignaturePermission() public {
        // make the message hash
        bytes32 plainHash = keccak256("Message to sign");

        // make 712 hash
        // SKIP FOR NOW as 7579 reference implementation doesn't support it
        bytes32 typedDataHash = plainHash;

        // sign hash
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner1Pk, typedDataHash);

        // append the signature with 1271+712 data
        // SKIP FOR NOW 
        // as 7579 reference implementation doesn't support it

        // prepend the signature with PermissionManager-specific data
        bytes memory signature  = abi.encodePacked(
            bytes1(0x00), //not enable mode
            signerId,
            r,s,v
        );

        // prepend the signature with PermissionManager address
        signature = abi.encodePacked(address(permissionManager), signature);

        // should not pass immediately
        assertEq(bytes4(0xFFFFFFFF), IERC1271(instance.account).isValidSignature(plainHash, signature));

        // should pass after the vm.warp
        vm.warp(block.timestamp + 501);
        assertEq(EIP1271_MAGIC_VALUE, IERC1271(instance.account).isValidSignature(plainHash, signature));

    }
}