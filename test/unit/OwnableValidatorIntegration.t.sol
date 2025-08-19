// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "../Base.t.sol";
import { OwnableValidator } from "test/unit/FlattenedOwnableValidator.sol";
import "solady/utils/ECDSA.sol";
import { PackedUserOperation } from "modulekit/ModuleKit.sol";

/**
 * @title OwnableValidatorIntegration
 * @dev Comprehensive test demonstrating OwnableValidator usage as a stateless validator in Smart Sessions
 * Tests the complete flow from session creation to transaction execution with edge cases
 */
contract OwnableValidatorIntegrationTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    /*//////////////////////////////////////////////////////////////////////////
                                    CONTRACTS
    //////////////////////////////////////////////////////////////////////////*/

    OwnableValidator internal ownableValidator;

    /*//////////////////////////////////////////////////////////////////////////
                                    VARIABLES
    //////////////////////////////////////////////////////////////////////////*/

    // Test signers (DApp + Backend) - properly sorted for OwnableValidator
    address[] internal owners;
    uint256[] internal ownerPks;
    uint256 internal threshold;

    // Session salt
    bytes32 internal constant SESSION_SALT = 0x3100000000000000000000000000000000000000000000000000000000000000;

    /*//////////////////////////////////////////////////////////////////////////
                                      SETUP
    //////////////////////////////////////////////////////////////////////////*/

    function setUp() public virtual override {
        super.setUp();

        // Deploy OwnableValidator
        ownableValidator = new OwnableValidator();

        // Create properly sorted signers for multisig
        _setupSortedOwners();

        // Require all signers to sign (DApp + Backend)
        threshold = owners.length;
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////////////////*/

    function _setupSortedOwners() internal {
        owners = new address[](2);
        ownerPks = new uint256[](2);

        (address owner1, uint256 owner1Pk) = makeAddrAndKey("dappSigner");
        (address owner2, uint256 owner2Pk) = makeAddrAndKey("backendSigner");

        // Ensure proper sorting (OwnableValidator requires sorted owners)
        if (uint160(owner1) < uint160(owner2)) {
            owners[0] = owner1;
            ownerPks[0] = owner1Pk;
            owners[1] = owner2;
            ownerPks[1] = owner2Pk;
        } else {
            owners[0] = owner2;
            ownerPks[0] = owner2Pk;
            owners[1] = owner1;
            ownerPks[1] = owner1Pk;
        }
    }

    function _createSession(uint256 _threshold, address[] memory _owners) internal returns (Session memory) {
        bytes memory ownableValidatorInitData = abi.encode(_threshold, _owners);

        return Session({
            sessionValidator: ISessionValidator(address(ownableValidator)),
            salt: SESSION_SALT,
            sessionValidatorInitData: ownableValidatorInitData,
            userOpPolicies: _getEmptyPolicyDatas(address(sudoPolicy)),
            erc7739Policies: _getEmptyERC7739Data("0", new PolicyData[](0)),
            actions: _getContractCallActions(),
            permitERC4337Paymaster: true
        });
    }

    function _enableSession(Session memory session) internal returns (PermissionId) {
        Session[] memory sessions = new Session[](1);
        sessions[0] = session;

        vm.prank(instance.account);
        PermissionId[] memory permissionIds = smartSession.enableSessions(sessions);
        return permissionIds[0];
    }

    function _executeWithSession(PermissionId permissionId, uint256 value) internal returns (UserOpData memory) {
        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (value)),
            txValidator: address(smartSession)
        });

        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId, sig: _createOwnableSignatures(userOpData.userOp) });

        userOpData.execUserOps();
        return userOpData;
    }

    function _getContractCallActions() internal view returns (ActionData[] memory) {
        ActionData[] memory actions = new ActionData[](1);
        actions[0] = ActionData({
            actionTarget: address(target),
            actionTargetSelector: MockTarget.setValue.selector,
            actionPolicies: _getEmptyPolicyDatas(address(sudoPolicy))
        });
        return actions;
    }

    function _createOwnableSignatures(PackedUserOperation memory userOp) internal view returns (bytes memory) {
        bytes32 userOpHash = instance.aux.entrypoint.getUserOpHash(userOp);

        // OwnableValidator calls ECDSA.toEthSignedMessageHash(hash) internally
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPks[0], ethHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPks[1], ethHash);

        // Pack signatures in the format expected by OwnableValidator: {r}{s}{v} concatenated
        return abi.encodePacked(r1, s1, v1, r2, s2, v2);
    }

    function _createInsufficientSignatures(PackedUserOperation memory userOp) internal view returns (bytes memory) {
        bytes32 userOpHash = instance.aux.entrypoint.getUserOpHash(userOp);
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(userOpHash);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPks[0], ethHash);

        // Only one signature (insufficient for threshold of 2)
        return abi.encodePacked(r1, s1, v1);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   CORE TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Test complete OwnableValidator session flow with Smart Sessions
     */
    function test_ownableValidatorSessionFlow() public {
        // Create and enable session
        Session memory session = _createSession(threshold, owners);
        PermissionId permissionId = _enableSession(session);

        // Verify the session is enabled
        assertTrue(smartSession.isPermissionEnabled(permissionId, instance.account));

        // Execute first transaction
        _executeWithSession(permissionId, 1337);
        assertEq(target.value(), 1337);

        // Execute second transaction using same session
        _executeWithSession(permissionId, 1338);
        assertEq(target.value(), 1338);
    }

    /**
     * @dev Test OwnableValidator stateless validation directly
     */
    function test_ownableValidatorStatelessValidation() public {
        bytes32 testHash = keccak256("test message");
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(testHash);

        // Create signatures from both owners (in sorted order)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPks[0], ethHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPks[1], ethHash);

        bytes memory combinedSignature = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        bytes memory validatorData = abi.encode(threshold, owners);

        // Test direct stateless validation
        bool isValid = ownableValidator.validateSignatureWithData(testHash, combinedSignature, validatorData);

        assertTrue(isValid, "Signature should be valid");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  THRESHOLD TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Test session creation with different threshold configurations
     */
    function test_ownableValidatorDifferentThresholds() public {
        // Test with threshold of 1 (any signer can authorize)
        uint256 relaxedThreshold = 1;
        Session memory session = _createSession(relaxedThreshold, owners);
        PermissionId permissionId = _enableSession(session);

        // Verify session is enabled
        assertTrue(smartSession.isPermissionEnabled(permissionId, instance.account));
    }

    /**
     * @dev Test that threshold of 0 fails validation
     */
    function test_ownableValidatorThresholdZeroFails() public {
        bytes32 testHash = keccak256("test message");
        bytes memory validatorData = abi.encode(0, owners); // threshold = 0
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        bool isValid = ownableValidator.validateSignatureWithData(testHash, signature, validatorData);

        assertFalse(isValid, "Threshold of 0 should fail");
    }

    /*//////////////////////////////////////////////////////////////////////////
                                   ERROR TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Test that insufficient signatures fail validation
     */
    function test_ownableValidatorInsufficientSignatures() public {
        bytes32 testHash = keccak256("test message");
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(testHash);

        // Only one signature (insufficient for threshold of 2)
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerPks[0], ethHash);
        bytes memory insufficientSignature = abi.encodePacked(r1, s1, v1);
        bytes memory validatorData = abi.encode(threshold, owners);

        // Should revert when insufficient signatures provided
        vm.expectRevert();
        ownableValidator.validateSignatureWithData(testHash, insufficientSignature, validatorData);
    }

    /**
     * @dev Test that unsorted owners fail validation
     */
    function test_ownableValidatorUnsortedOwnersFail() public {
        bytes32 testHash = keccak256("test message");

        // Create unsorted owners array
        address[] memory unsortedOwners = new address[](2);
        unsortedOwners[0] = owners[1]; // Swap order
        unsortedOwners[1] = owners[0];

        bytes memory validatorData = abi.encode(threshold, unsortedOwners);
        bytes memory signature = abi.encodePacked(bytes32(0), bytes32(0), uint8(0));

        bool isValid = ownableValidator.validateSignatureWithData(testHash, signature, validatorData);

        assertFalse(isValid, "Unsorted owners should fail");
    }

    /**
     * @dev Test that wrong signer fails validation
     */
    function test_ownableValidatorWrongSignerFails() public {
        bytes32 testHash = keccak256("test message");
        bytes32 ethHash = ECDSA.toEthSignedMessageHash(testHash);

        // Create signature with wrong signer
        (address wrongSigner, uint256 wrongPk) = makeAddrAndKey("wrongSigner");
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(wrongPk, ethHash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerPks[1], ethHash);

        bytes memory wrongSignature = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        bytes memory validatorData = abi.encode(threshold, owners);

        bool isValid = ownableValidator.validateSignatureWithData(testHash, wrongSignature, validatorData);

        assertFalse(isValid, "Wrong signer should fail");
    }

    /**
     * @dev Test session execution with insufficient signatures fails
     */
    function test_sessionExecutionWithInsufficientSignaturesFails() public {
        Session memory session = _createSession(threshold, owners);
        PermissionId permissionId = _enableSession(session);

        UserOpData memory userOpData = instance.getExecOps({
            target: address(target),
            value: 0,
            callData: abi.encodeCall(MockTarget.setValue, (1337)),
            txValidator: address(smartSession)
        });

        // Use insufficient signatures
        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId, sig: _createInsufficientSignatures(userOpData.userOp) });

        // Should fail during execution
        vm.expectRevert();
        userOpData.execUserOps();
    }

    /*//////////////////////////////////////////////////////////////////////////
                                  EDGE CASE TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Test with maximum number of owners
     */
    function test_ownableValidatorManyOwners() public {
        // Create session with 5 owners, threshold 3
        address[] memory manyOwners = new address[](5);
        uint256[] memory manyOwnerPks = new uint256[](5);

        for (uint256 i = 0; i < 5; i++) {
            (manyOwners[i], manyOwnerPks[i]) = makeAddrAndKey(string(abi.encodePacked("owner", i)));
        }

        // Sort owners (simple bubble sort for test)
        for (uint256 i = 0; i < manyOwners.length - 1; i++) {
            for (uint256 j = 0; j < manyOwners.length - i - 1; j++) {
                if (uint160(manyOwners[j]) > uint160(manyOwners[j + 1])) {
                    // Swap addresses
                    address tempAddr = manyOwners[j];
                    manyOwners[j] = manyOwners[j + 1];
                    manyOwners[j + 1] = tempAddr;

                    // Swap private keys
                    uint256 tempPk = manyOwnerPks[j];
                    manyOwnerPks[j] = manyOwnerPks[j + 1];
                    manyOwnerPks[j + 1] = tempPk;
                }
            }
        }

        uint256 manyThreshold = 3;
        Session memory session = _createSession(manyThreshold, manyOwners);
        PermissionId permissionId = _enableSession(session);

        assertTrue(smartSession.isPermissionEnabled(permissionId, instance.account));
    }

    /**
     * @dev Test empty owners array fails
     */
    function test_ownableValidatorEmptyOwnersFails() public {
        address[] memory emptyOwners = new address[](0);
        bytes32 testHash = keccak256("test message");
        bytes memory validatorData = abi.encode(1, emptyOwners);
        bytes memory signature = "";

        // Should revert with InvalidSignature for empty owners
        vm.expectRevert();
        ownableValidator.validateSignatureWithData(testHash, signature, validatorData);
    }

    /*//////////////////////////////////////////////////////////////////////////
                                INTEGRATION TESTS
    //////////////////////////////////////////////////////////////////////////*/

    /**
     * @dev Test session reuse across multiple transactions
     */
    function test_sessionReuseAcrossMultipleTransactions() public {
        Session memory session = _createSession(threshold, owners);
        PermissionId permissionId = _enableSession(session);

        // Execute multiple transactions with same session
        uint256[] memory values = new uint256[](5);
        values[0] = 100;
        values[1] = 200;
        values[2] = 300;
        values[3] = 400;
        values[4] = 500;

        for (uint256 i = 0; i < values.length; i++) {
            _executeWithSession(permissionId, values[i]);
            assertEq(target.value(), values[i]);
        }
    }

    /**
     * @dev Test multiple sessions with different configurations
     */
    function test_multipleSessionsWithDifferentConfigurations() public {
        // Session 1: Threshold 2
        Session memory session1 = _createSession(2, owners);
        PermissionId permissionId1 = _enableSession(session1);

        // Session 2: Threshold 1
        Session memory session2 = _createSession(1, owners);
        session2.salt = bytes32(uint256(SESSION_SALT) + 1); // Different salt
        PermissionId permissionId2 = _enableSession(session2);

        // Both sessions should be enabled
        assertTrue(smartSession.isPermissionEnabled(permissionId1, instance.account));
        assertTrue(smartSession.isPermissionEnabled(permissionId2, instance.account));

        // Both should work
        _executeWithSession(permissionId1, 1000);
        assertEq(target.value(), 1000);

        _executeWithSession(permissionId2, 2000);
        assertEq(target.value(), 2000);
    }
}
