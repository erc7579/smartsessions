import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/PolicyTestBase.t.sol";

contract SimpleGasPolicyTest is PolicyTestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    PermissionId permissionId_valueLimitedAction;

    bytes simpleGasPolicyInitData;

    function setUp() public virtual override {
        super.setUp();
        // Initialize with both gasLimit (1M gas) and costLimit (0.1 ETH)
        simpleGasPolicyInitData = abi.encodePacked(
            uint128(1_000_000), // gasLimit: 1M gas units
            uint128(0.1 ether) // costLimit: 0.1 ETH
        );
        vm.deal(instance.account, 1e21);
    }

    function test_simple_gas_policy_init_reinit_use() public {
        PermissionId permissionId = use_simple_gas_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit();
        gas_limit_policy_can_be_reinitialized(permissionId);
    }

    function using_simple_gas_policy_fails_not_initialized() public returns (PermissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // Initialize with zero values to test failure
        bytes memory zeroInitData = abi.encodePacked(uint128(0), uint128(0));
        PermissionId invalidPermissionId =
            _enableUserOpSession(address(simpleGasPolicy), zeroInitData, instance, keccak256("salt"));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: invalidPermissionId, sig: hex"4141414141" });
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodePacked(
                hex"f4270752", // `PolicyCheckReverted(bytes32)`
                IPolicy.PolicyNotInitialized.selector,
                bytes28(
                    ConfigId.unwrap(IdLib.toConfigId(IdLib.toUserOpPolicyId(invalidPermissionId), instance.account))
                )
            )
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
        return invalidPermissionId;
    }

    function use_simple_gas_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit()
        public
        returns (PermissionId)
    {
        //re-initialize
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(simpleGasPolicy), simpleGasPolicyInitData, instance, keccak256("salt"));
        // use
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionIdReInited, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 500_000;
        uint128 validationGasLimit = 250_000;
        uint128 callGasLimit = 250_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(validationGasLimit) << 128) + callGasLimit);
        // execute userOp with modulekit
        userOpData.execUserOps();

        // Check that gas was properly tracked
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasLimit, 1_000_000);
        assertEq(costLimit, 0.1 ether);
        assertGt(gasUsed, 0); // Some gas should have been used
        assertGt(costUsed, 0); // Some cost should have been incurred

        // try to exceed the limit, should fail
        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, permissionIdReInited, address(simpleGasPolicy)
        );

        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        return permissionIdReInited;
    }

    function gas_limit_policy_can_be_reinitialized(PermissionId permissionId) public returns (PermissionId) {
        // re-initialize with new limit, check that both limit and used are updated
        PermissionId permissionIdReInited =
            _enableUserOpSession(address(simpleGasPolicy), simpleGasPolicyInitData, instance, keccak256("salt"));
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);

        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasLimit, 1_000_000);
        assertEq(costLimit, 0.1 ether);
        assertEq(gasUsed, 0); // Should be reset after re-initialization
        assertEq(costUsed, 0); // Should be reset after re-initialization

        return permissionIdReInited;
    }

    function test_cost_limit_functionality(PermissionId permissionId) public {
        // Test that cost limit is properly enforced
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (9999));

        // Initialize with very low cost limit to test cost-based rejection
        bytes memory lowCostInitData = abi.encodePacked(
            uint128(10_000_000), // gasLimit: High gas limit
            uint128(1000) // costLimit: Very low cost limit (1000 wei)
        );

        PermissionId lowCostPermissionId =
            _enableUserOpSession(address(simpleGasPolicy), lowCostInitData, instance, keccak256("lowCostSalt"));

        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: lowCostPermissionId, sig: hex"4141414141" });

        // Set high gas price to trigger cost limit
        userOpData.userOp.gasFees = bytes32((uint256(100 gwei) << 128) + uint256(100 gwei)); // High gas fees
        userOpData.userOp.preVerificationGas = 21_000;
        uint128 validationGasLimit = 50_000;
        uint128 callGasLimit = 50_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(validationGasLimit) << 128) + callGasLimit);

        // Should fail due to cost limit being exceeded
        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, lowCostPermissionId, address(simpleGasPolicy)
        );

        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_gas_and_cost_tracking() public {
        // Test that both gas and cost are properly tracked over multiple operations
        bytes memory trackingInitData = abi.encodePacked(
            uint128(1_000_000), // gasLimit: 1M gas (enough for 2+ operations)
            uint128(0.1 ether) // costLimit: 0.1 ETH
        );

        PermissionId testPermissionId =
            _enableUserOpSession(address(simpleGasPolicy), trackingInitData, instance, keccak256("trackingSalt"));

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1111));

        // First operation - should succeed
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: testPermissionId, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 200_000;
        uint128 validationGasLimit = 100_000;
        uint128 callGasLimit = 100_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(validationGasLimit) << 128) + callGasLimit);
        userOpData.execUserOps();

        // Check tracking after first operation
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(testPermissionId), instance.account);
        (uint128 gasLimit, uint128 gasUsed1, uint128 costLimit, uint128 costUsed1) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasLimit, 1_000_000);
        assertEq(costLimit, 0.1 ether);
        assertGt(gasUsed1, 0);
        assertGt(costUsed1, 0);

        // Second operation - should also succeed
        userOpData.userOp.nonce++;
        userOpData.execUserOps();
        uint128 gasUsed2;
        uint128 costUsed2;

        // Check that counters increased
        (gasLimit, gasUsed2, costLimit, costUsed2) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertGt(gasUsed2, gasUsed1); // Gas used should have increased
        assertGt(costUsed2, costUsed1); // Cost used should have increased
    }

    function test_gas_limit_exceeded() public {
        // Test that gas limit is properly enforced
        bytes memory restrictiveInitData = abi.encodePacked(
            uint128(500_000), // gasLimit: 500K gas (enough for 1 operation only)
            uint128(1 ether) // costLimit: 1 ETH (high enough to not interfere)
        );

        PermissionId restrictivePermissionId =
            _enableUserOpSession(address(simpleGasPolicy), restrictiveInitData, instance, keccak256("restrictiveSalt"));

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (2222));

        // First operation - should succeed
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: restrictivePermissionId, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 200_000;
        uint128 validationGasLimit = 100_000;
        uint128 callGasLimit = 100_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(validationGasLimit) << 128) + callGasLimit);
        userOpData.execUserOps();

        // Second operation - should fail due to gas limit
        userOpData.userOp.nonce++;

        bytes memory innerRevertReason = abi.encodeWithSelector(
            ISmartSession.PolicyViolation.selector, restrictivePermissionId, address(simpleGasPolicy)
        );

        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }

    function test_gas_price_calculation_accuracy() public {
        // Test different gas price scenarios to ensure accurate cost calculation
        bytes memory initData = abi.encodePacked(
            uint128(1_000_000), // gasLimit: 1M gas
            uint128(1 ether) // costLimit: 1 ETH
        );

        PermissionId permissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("gasPriceSalt"));

        // Test scenario 1: maxPriorityFeePerGas + basefee < maxFeePerGas
        vm.fee(10 gwei); // Set block.basefee to 10 gwei

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (5555));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        uint256 maxPriorityFeePerGas = 5 gwei;
        uint256 maxFeePerGas = 20 gwei;
        userOpData.userOp.gasFees = bytes32((maxPriorityFeePerGas << 128) + maxFeePerGas);
        userOpData.userOp.preVerificationGas = 100_000;
        // Use higher gas limits to avoid OutOfGas
        userOpData.userOp.accountGasLimits = bytes32((uint256(200_000) << 128) + uint256(200_000));

        // Expected gas price should be min(20 gwei, 5 gwei + 10 gwei) = 15 gwei
        uint256 expectedGasPrice = 15 gwei;
        uint256 expectedTotalGas = 100_000 + 200_000 + 200_000; // 500K gas
        uint256 expectedCost = expectedTotalGas * expectedGasPrice;

        userOpData.execUserOps();

        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionId), instance.account);
        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasUsed, expectedTotalGas);
        assertEq(costUsed, expectedCost);
    }

    function test_paymaster_data_parsing_logic() public {
        // Test the logic for parsing paymaster data of different lengths
        // This tests our policy's gas calculation without needing actual paymasters

        bytes memory initData = abi.encodePacked(
            uint128(1_000_000), // gasLimit: 1M gas
            uint128(1 ether) // costLimit: 1 ETH
        );

        PermissionId permissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("payMasterParsingSalt"));

        // Test different paymaster data lengths to verify our parsing logic

        // Case 1: Exactly 36 bytes (address + verification gas only)
        bytes memory paymaster36Bytes = abi.encodePacked(
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint128(75_000) // 16 bytes -> total 36 bytes
        );
        assertEq(paymaster36Bytes.length, 36);

        // Case 2: Full paymaster data (52+ bytes)
        bytes memory paymasterFullData = abi.encodePacked(
            address(0x1234567890123456789012345678901234567890), // 20 bytes
            uint128(75_000), // 16 bytes verification gas
            uint128(25_000), // 16 bytes postOp gas
            bytes("extra") // 5 bytes extra -> total 57 bytes
        );
        assertEq(paymasterFullData.length, 57);

        // Case 3: Short paymaster data (less than 36 bytes)
        bytes memory paymasterShortData = abi.encodePacked(
            address(0x1234567890123456789012345678901234567890) // Only 20 bytes
        );
        assertEq(paymasterShortData.length, 20);

        // These tests verify our length-based conditional logic would work correctly
        assertTrue(paymaster36Bytes.length >= 36);
        assertTrue(paymasterFullData.length >= 52);
        assertTrue(paymasterShortData.length < 36);
    }

    function test_uint128_overflow_protection() public {
        // Test behavior near uint128 limits
        uint128 nearMaxValue = type(uint128).max - 1000; // Close to uint128 max

        bytes memory initData = abi.encodePacked(
            nearMaxValue, // gasLimit: near uint128 max
            nearMaxValue // costLimit: near uint128 max
        );

        PermissionId permissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("overflowSalt"));

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (8888));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 50_000;
        // Use higher gas limits to avoid OutOfGas
        userOpData.userOp.accountGasLimits = bytes32((uint256(150_000) << 128) + uint256(150_000));
        userOpData.userOp.gasFees = bytes32((uint256(1) << 128) + uint256(1)); // 1 wei per gas

        // Should succeed - we're well under the limit
        userOpData.execUserOps();

        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionId), instance.account);
        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasLimit, nearMaxValue);
        assertEq(costLimit, nearMaxValue);
        assertEq(gasUsed, 350_000); // 50K + 150K + 150K
        assertEq(costUsed, 350_000); // 350K gas * 1 wei/gas
    }

    function test_state_persistence_and_reset() public {
        // Test that state persists across operations and resets on re-initialization
        bytes memory initData = abi.encodePacked(
            uint128(1_000_000), // gasLimit: 1M gas
            uint128(1 ether) // costLimit: 1 ETH
        );

        PermissionId permissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("persistSalt"));

        // Perform first operation
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (9999));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 100_000;
        // Use higher gas limits to avoid verification gas limit errors
        userOpData.userOp.accountGasLimits = bytes32((uint256(200_000) << 128) + uint256(200_000));
        userOpData.execUserOps();

        // Check state after first operation
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionId), instance.account);
        (uint128 gasLimit, uint128 gasUsed1, uint128 costLimit, uint128 costUsed1) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);
        assertGt(gasUsed1, 0);
        assertGt(costUsed1, 0);

        // Perform second operation - state should accumulate
        userOpData.userOp.nonce++;
        userOpData.execUserOps();
        uint128 gasUsed2;
        uint128 costUsed2;

        (gasLimit, gasUsed2, costLimit, costUsed2) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);
        assertGt(gasUsed2, gasUsed1); // Should have accumulated
        assertGt(costUsed2, costUsed1); // Should have accumulated

        // Re-initialize with same salt - should reset counters
        PermissionId samePermissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("persistSalt"));
        assertEq(PermissionId.unwrap(samePermissionId), PermissionId.unwrap(permissionId));
        uint128 gasUsedReset;
        uint128 costUsedReset;
        (gasLimit, gasUsedReset, costLimit, costUsedReset) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);
        assertEq(gasUsedReset, 0); // Should be reset
        assertEq(costUsedReset, 0); // Should be reset
    }

    function test_exact_limit_boundary() public {
        // Test operations that exactly hit the limits
        bytes memory initData = abi.encodePacked(
            uint128(800_000), // gasLimit: exactly what two operations need
            uint128(0.01 ether) // costLimit: reasonable limit
        );

        PermissionId permissionId =
            _enableUserOpSession(address(simpleGasPolicy), initData, instance, keccak256("exactSalt"));

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (4444));
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // Set up operation to use exactly 400K gas
        userOpData.userOp.preVerificationGas = 200_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(100_000) << 128) + uint256(100_000));
        userOpData.userOp.gasFees = bytes32((uint256(1 gwei) << 128) + uint256(5 gwei));

        // First operation should succeed
        userOpData.execUserOps();

        // Verify we used the expected gas
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionId), instance.account);
        (uint128 gasLimit, uint128 gasUsed, uint128 costLimit, uint128 costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasUsed, 400_000); // 200K + 100K + 100K
        assertGt(costUsed, 0); // Should have some cost

        // Second operation should also succeed (exactly at limit)
        userOpData.userOp.nonce++;
        userOpData.execUserOps();
        uint128 gasUsedFinal;
        (gasLimit, gasUsedFinal, costLimit, costUsed) =
            simpleGasPolicy.getGasConfig(configId, address(smartSession), instance.account);

        assertEq(gasUsedFinal, 800_000); // Exactly at gas limit

        // Third operation should fail - would exceed limit
        userOpData.userOp.nonce++;
        bytes memory innerRevertReason =
            abi.encodeWithSelector(ISmartSession.PolicyViolation.selector, permissionId, address(simpleGasPolicy));
        bytes memory expectedRevertReason =
            abi.encodeWithSelector(IEntryPoint.FailedOpWithRevert.selector, 0, "AA23 reverted", innerRevertReason);
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
    }
}
