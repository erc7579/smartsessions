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
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, Execution } from "modulekit/external/ERC7579.sol";
import { PermissionManager } from "contracts/validators/PermissionManager.sol";
import { SimpleSigner } from "contracts/test/mocks/SimpleSigner.sol";
import { UsageLimitPolicy } from "contracts/test/mocks/UsageLimitPolicy.sol";
import { SimpleGasPolicy } from "contracts/test/mocks/SimpleGasPolicy.sol";
import { TimeFramePolicy } from "contracts/test/mocks/TimeFramePolicy.sol";
import { Counter } from "contracts/test/Counter.sol";
import { MockValidator } from "contracts/test/mocks/MockValidator.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";
import { UserOperationBuilder } from "contracts/utils/UserOpBuilder.sol";
import { ModeLib } from "contracts/utils/lib/ModeLib.sol";
import { LibZip } from "solady/utils/LibZip.sol";

import "forge-std/console2.sol";

contract PermissionManagerBaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using LibZip for bytes;

    // account and modules
    AccountInstance internal instance;
    PermissionManager internal permissionManager;
    MockValidator mockValidator;
    
    bytes32 signerId;

    SimpleSigner internal simpleSignerValidator;
    address sessionSigner1;
    uint256 sessionSigner1Pk;
    address sessionSigner2;
    uint256 sessionSigner2Pk;
    address owner;
    uint256 ownerPk;

    UsageLimitPolicy internal usageLimitPolicy;
    SimpleGasPolicy internal simpleGasPolicy;
    TimeFramePolicy internal timeFramePolicy;

    Counter counterContract;

    function setUp() public {
        init();

        // Create the counter contract
        counterContract = new Counter();

        // Create the validators
        permissionManager = new PermissionManager();
        vm.label(address(permissionManager), "PermissionManager");
        mockValidator = new MockValidator();
        vm.label(address(mockValidator), "MockValidator");

        // Create the signer validator
        simpleSignerValidator = new SimpleSigner();
        vm.label(address(simpleSignerValidator), "SimpleSignerValidator");

        // Deploy Policies
        usageLimitPolicy = new UsageLimitPolicy();
        vm.label(address(usageLimitPolicy), "UsageLimitPolicy");
        console2.log("Usage limit policy address: ", address(usageLimitPolicy));
        simpleGasPolicy = new SimpleGasPolicy();
        vm.label(address(simpleGasPolicy), "SimpleGasPolicy");
        timeFramePolicy = new TimeFramePolicy();
        vm.label(address(timeFramePolicy), "TimeFramePolicy");

        // Create the account and install PermissionManager as a validator and as an executor
        instance = makeAccountInstance("PermissionManager");
        vm.deal(address(instance.account), 10 ether);

        (owner, ownerPk) = makeAddrAndKey("owner");
        (sessionSigner1, sessionSigner1Pk) = makeAddrAndKey("sessionSigner1");
        (sessionSigner2, sessionSigner2Pk) = makeAddrAndKey("sessionSigner2");

        // INSTALL MOCK validator and set ownership
        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockValidator),
            data: abi.encodePacked(owner)
        });


        //example signerId
        signerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp));

        instance.installModule({
            moduleTypeId: MODULE_TYPE_EXECUTOR,
            module: address(permissionManager),
            data: abi.encodePacked(bytes1(uint8(MODULE_TYPE_EXECUTOR)))
        });

        // ======== Construct Permission Data =========
        bytes4 permissionDataStructureDescriptor = bytes4(
            (uint32(1) << 24) + // setup signer mode = true
            (uint32(2) << 16) + // number of userOp policies
            (uint32(2) << 8) + // number of action policies
            uint32(1) // number of 1271 policies
        );
        //console2.logBytes4(permissionDataStructureDescriptor);

        // initial data and signer Id config
        bytes memory permissionDataWithMode = abi.encodePacked(
            uint8(MODULE_TYPE_VALIDATOR), //1 byte
            signerId,
            permissionDataStructureDescriptor,
            simpleSignerValidator,  //signer validator
            uint32(20), // signer validator config data length
            sessionSigner1 // signer validator config data
        );

        // userOp policies
        permissionDataWithMode = abi.encodePacked(
            permissionDataWithMode,
            address(usageLimitPolicy), // usageLimitPolicy address
            uint32(32), // usageLimitPolicy config data length
            uint256(10), // limit
            address(simpleGasPolicy), // simpleGasPolicy address
            uint32(32), // simpleGasPolicy config data length
            uint256(2**256-1) // limit
        );

        bytes32 actionId = keccak256(abi.encodePacked(address(counterContract), counterContract.incr.selector));//action Id

        // action policies
        permissionDataWithMode = abi.encodePacked(
            permissionDataWithMode,
            actionId,
            address(usageLimitPolicy),
            uint32(32), // usageLimitPolicy config data length
            uint256(5), // limit
            address(timeFramePolicy),
            uint32(32), // timeFramePolicy config data length
            uint256(((block.timestamp + 1000) << 128) + (block.timestamp ))
        );

        // 1271 policies
        permissionDataWithMode = abi.encodePacked(
            permissionDataWithMode,
            address(timeFramePolicy),
            uint32(32), // timeFramePolicy config data length
            uint256(((block.timestamp + 11111) << 128) + (block.timestamp + 500))
        );

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(permissionManager),
            data: permissionDataWithMode
        });

        assertTrue(simpleSignerValidator.isInitialized(instance.account));
        assertTrue(usageLimitPolicy.isInitialized(instance.account));
        assertTrue(simpleGasPolicy.isInitialized(instance.account));
        
    }

    function testSingleExec() public {
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

    function testBatchExec() public {
        uint256 value = 1 ether;
        uint256 numberOfExecs = 3;

        // Get the current balance of the target
        uint256 prevBalance = address(counterContract).balance;

        Execution[] memory executions = new Execution[](numberOfExecs);
        for (uint256 i = 0; i < numberOfExecs; i++) {
            executions[i] = Execution({
                target: address(counterContract),
                value: value,
                callData: abi.encodeWithSelector(counterContract.incr.selector)
            });
        }

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            executions: executions,
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
        assertEq(address(counterContract).balance, prevBalance+value*numberOfExecs, "Balance not increased");
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

    function testEnableAndUsePermission() public {
        //make new signerId
        bytes32 newSignerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp+1000));

        assertFalse(permissionManager.isSignerIdEnabledOnchain(newSignerId, instance.account));

        uint256 value = 1 ether;
        uint256 prevBalance = address(counterContract).balance;

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            target: address(counterContract),
            value: value,
            callData: abi.encodeWithSelector(counterContract.incr.selector),
            txValidator: address(permissionManager)
        });

        // ======== sign the userOp with the newly enabled signer ============================
        bytes memory cleanSig;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner2Pk, userOpData.userOpHash);
            cleanSig = abi.encodePacked(r,s,v);
        }
        
        (bytes memory permissionData,
        bytes memory permissionEnableData,
        bytes memory permissionEnableDataSignature) = _getTestPermissionEnableContext(
            newSignerId,
            address(simpleSignerValidator),
            abi.encodePacked(sessionSigner2),
            address(usageLimitPolicy),
            address(simpleGasPolicy),
            address(timeFramePolicy),
            ownerPk
        );

        // 1. clean zeroes before appending cleanSig => save on calldata for l2's
        // and some gas on-chain when parsing cleanSig.
        bytes memory signature = _cutTrailingZeroes(
            abi.encode(
                permissionEnableData,
                permissionEnableDataSignature,
                permissionData
            )
        );

        // 2. we abi.encode.packed cleanSig to avoid appended zeroes
        signature = abi.encodePacked(
            bytes1(0x01), //Enable mode
            uint8(1), // index of permission in sessionEnableData
            signature,
            cleanSig
        );

        userOpData.userOp.signature = signature;
        
        // Execute the UserOp
        userOpData.execUserOps();

        // Check if the balance of the target has NOT increased
        assertEq(address(counterContract).balance, prevBalance+value, "Balance not increased");

        // Check isPermissionEnabled after permission was in fact enabled. 
        bytes memory partialContext = abi.encodePacked(
            uint8(1), // index of permission in sessionEnableData
            abi.encode(
                permissionEnableData,
                permissionEnableDataSignature,
                permissionData 
            )
        );
        (bool res, ) = permissionManager.isPermissionEnabled(partialContext, instance.account);
        assertTrue(res);
    }    

    function testUserOpBuilderGeneralFlow() public {
        // try to format a userOp with userOpBuilder

        address ep = address(instance.aux.entrypoint);        
        //deploy userOpBuilder
        UserOperationBuilder userOpBuilder = new UserOperationBuilder(ep);

        //make new signerId
        bytes32 newSignerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp+1000));

        assertFalse(permissionManager.isSignerIdEnabledOnchain(newSignerId, instance.account));

        uint256 value = 1 ether;
        uint256 prevBalance = address(counterContract).balance;

        // Get the UserOp data (UserOperation and UserOperationHash)
        UserOpData memory userOpData = instance.getExecOps({
            target: address(0),
            value: 0,
            callData: "",
            txValidator: address(permissionManager)
        });
   
        // build the context
        (bytes memory permissionData,
        bytes memory permissionEnableData,
        bytes memory permissionEnableDataSignature) = _getTestPermissionEnableContext(
            newSignerId,
            address(simpleSignerValidator),
            abi.encodePacked(sessionSigner2),
            address(usageLimitPolicy),
            address(simpleGasPolicy),
            address(timeFramePolicy),
            ownerPk
        );

        uint192 nonceKey = uint192(uint160(address(permissionManager))) << 32;
        //console2.logBytes24(bytes24(nonceKey));

        bytes memory context = abi.encodePacked(
            nonceKey, 
            ModeLib.encodeSimpleSingle(), //execution mode
            uint8(1), // index of permission in sessionEnableData
            abi.encode(
                permissionEnableData,
                permissionEnableDataSignature,
                permissionData
            )
        );

        // get nonce and calldata and replace it in the userOp
        uint256 nonce = userOpBuilder.getNonce(instance.account, context);

        Execution[] memory executions = new Execution[](1);
        executions[0] = Execution(
            address(counterContract),
            value,
            abi.encodeWithSelector(counterContract.incr.selector)
        );
        bytes memory callData = userOpBuilder.getCallData(instance.account, executions, context);

        userOpData.userOp.nonce = nonce;
        userOpData.userOp.callData = callData;
        userOpData.userOpHash = instance.aux.entrypoint.getUserOpHash(userOpData.userOp);

        // ======== sign the userOp with the newly enabled signer ============================
        bytes memory cleanSig;
        {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(sessionSigner2Pk, userOpData.userOpHash);
            cleanSig = abi.encodePacked(r,s,v);
        }
        userOpData.userOp.signature = cleanSig;

        bytes memory formattedSig = userOpBuilder.formatSignature(instance.account, userOpData.userOp, context);
        // console2.logBytes(formattedSig);
        userOpData.userOp.signature = formattedSig;

        // Execute the UserOp
        userOpData.execUserOps();

        // TODO: try to format the new userOp via userOpBuilder and make sure it formats properly
        // after permission was
    }

    function testZip() public {

        //make new signerId
        bytes32 newSignerId = keccak256(abi.encodePacked("Signer Id for ", instance.account, simpleSignerValidator, block.timestamp+1000));

        // build the context
        (bytes memory permissionData,
        bytes memory permissionEnableData,
        bytes memory permissionEnableDataSignature) = _getTestPermissionEnableContext(
            newSignerId,
            address(simpleSignerValidator),
            abi.encodePacked(sessionSigner2),
            address(usageLimitPolicy),
            address(simpleGasPolicy),
            address(timeFramePolicy),
            ownerPk
        );

        uint192 nonceKey = uint192(uint160(address(permissionManager))) << 32;

        bytes memory context = abi.encode(
                permissionEnableData,
                permissionEnableDataSignature,
                permissionData
            );

        context = abi.encodePacked(
            nonceKey, 
            ModeLib.encodeSimpleSingle(), //execution mode
            uint8(1), // index of permission in sessionEnableData
            _cutTrailingZeroes(context)
        );

        bytes memory contextFzComp = context.flzCompress();
        bytes memory contextFzDecomp = contextFzComp.flzDecompress();

        bytes memory contextCdComp = context.cdCompress();
        bytes memory contextCdDecomp = context.cdDecompress();

        console2.logBytes(context);
        //console2.logBytes(contextFzDecomp);

        //console2.logBytes(contextFzComp);
    }


    // -=====

    // cut zeroes from abi.encoded data 
    function _cutTrailingZeroes(bytes memory data) internal view returns (bytes memory) {
        assembly {
            let ln := mload(data) //sub not abi.encoded prefix length
            let dataPointer := add(data, 0x20)
            let lo := mload(add(dataPointer, mul(0x20, 0x02)))
            let ll := mload(add(dataPointer, lo))
            let nz := sub(0x20, mod(ll, 0x20))
            mstore(data, sub(ln, nz))
        }
        return data;
    }

    function _getTestPermissionEnableContext(
        bytes32 newSignerId,
        address simpleSignerValidator,
        bytes memory signerValidatorConfigData,
        address usageLimitPolicy,
        address simpleGasPolicy,
        address timeFramePolicy,
        uint256 permissionEnableDataSignerPrivateKey
    ) internal view returns (
        bytes memory permissionData,
        bytes memory permissionEnableData,
        bytes memory permissionEnableDataSignature
    ) {
        // ======== Construct Permission Data =========
        bytes4 permissionDataStructureDescriptor = bytes4(
            (uint32(1) << 24) + // setup signer mode = true
            (uint32(2) << 16) + // number of userOp policies
            (uint32(2) << 8) + // number of action policies
            uint32(1) // number of 1271 policies
        );
        console2.logBytes4(permissionDataStructureDescriptor);

        // initial data and signer Id config
        permissionData = abi.encodePacked(
            newSignerId,
            permissionDataStructureDescriptor,
            simpleSignerValidator,  //signer validator
            uint32(20), // signer validator config data length
            signerValidatorConfigData // (should be just public address of the new session signer)
        );

        // userOp policies
        permissionData = abi.encodePacked(
            permissionData,
            address(usageLimitPolicy), // usageLimitPolicy address
            uint32(32), // usageLimitPolicy config data length
            uint256(10), // limit
            address(simpleGasPolicy), // simpleGasPolicy address
            uint32(32), // simpleGasPolicy config data length
            uint256(2**256-1) // limit
        );

        bytes32 actionId = keccak256(abi.encodePacked(address(counterContract), counterContract.incr.selector));//action Id

        // action policies
        permissionData = abi.encodePacked(
            permissionData,
            actionId,
            address(usageLimitPolicy),
            uint32(32), // usageLimitPolicy config data length
            uint256(5), // limit
            address(timeFramePolicy),
            uint32(32), // timeFramePolicy config data length
            uint256(((block.timestamp + 1000) << 128) + (block.timestamp ))
        );

        // 1271 policies
        permissionData = abi.encodePacked(
            permissionData,
            address(timeFramePolicy),
            uint32(32), // timeFramePolicy config data length
            uint256(((block.timestamp + 11111) << 128) + (block.timestamp + 500))
        );

        bytes32 permissionDigest = keccak256(permissionData);
        //console2.log("Permission digest");
        //console2.logBytes32(permissionDigest);

        // ========= Construct Session Enable Data ===========
        permissionEnableData = abi.encodePacked(
            //bytes1(0x02), // how many permissions is there
            uint64(0x01), //mainnet chaid
            permissionDigest,
            uint64(block.chainid), //localhost chainid
            permissionDigest
        );

        // ========= Sign the Session Enable Data Hash with owner's key ===========
        {
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(permissionEnableDataSignerPrivateKey, keccak256(permissionEnableData));
            permissionEnableDataSignature = abi.encodePacked(r1,s1,v1);
        }
        permissionEnableDataSignature = abi.encodePacked(address(mockValidator), permissionEnableDataSignature);
    }



}