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
        simpleGasPolicyInitData = abi.encodePacked(uint256(1_000_000));
        vm.deal(instance.account, 1e21);
    }

    function test_simple_gas_policy_init_reinit_use() public {
        PermissionId permissionId = using_simple_gas_policy_fails_not_initialized();
        permissionId = use_simple_gas_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit(permissionId);
        gas_limit_policy_can_be_reinitialized(permissionId);
    }

    function using_simple_gas_policy_fails_not_initialized() public returns (PermissionId) {
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        PermissionId invalidPermissionId = _enableUserOpSession(address(simpleGasPolicy), abi.encodePacked(uint256(0)), instance, keccak256("salt"));
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: invalidPermissionId, sig: hex"4141414141" });
        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodePacked(
                hex'f4270752', // `PolicyCheckReverted(bytes32)`
                IPolicy.PolicyNotInitialized.selector,
                bytes28(ConfigId.unwrap(IdLib.toConfigId(IdLib.toUserOpPolicyId(invalidPermissionId), instance.account)))
            )
        );
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(target.value(), 0);
        return invalidPermissionId;
    }

    function use_simple_gas_policy_as_UserOp_policy_success_and_fails_if_exceeds_limit(PermissionId permissionId) public returns (PermissionId) {
        //re-initialize
        PermissionId permissionIdReInited = _enableUserOpSession(address(simpleGasPolicy), simpleGasPolicyInitData, instance, keccak256("salt"));
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));
        // use
        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.userOp.preVerificationGas = 500_000;
        uint128 validationGasLimit = 250_000;
        uint128 callGasLimit = 250_000;
        userOpData.userOp.accountGasLimits = bytes32((uint256(validationGasLimit) << 128) + callGasLimit);
        // execute userOp with modulekit
        userOpData.execUserOps();

        // try to exceed the limit, should fail
        userOpData.userOp.nonce++;
        
        bytes memory innerRevertReason = abi.encodeWithSelector(
                ISmartSession.PolicyViolation.selector,
                permissionId,
                address(simpleGasPolicy)
        );

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            innerRevertReason
        );      
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        return permissionIdReInited;
    } 

    function gas_limit_policy_can_be_reinitialized(PermissionId permissionId) public returns (PermissionId) {
        // re-initialize with new limit, check that both limit and used are updated
        PermissionId permissionIdReInited = _enableUserOpSession(address(simpleGasPolicy), simpleGasPolicyInitData, instance, keccak256("salt"));
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));
        ConfigId configId = IdLib.toConfigId(IdLib.toUserOpPolicyId(permissionIdReInited), instance.account);
        assertEq(simpleGasPolicy.getGasLimit(configId, address(smartSession), instance.account), uint256(1_000_000));
        assertEq(simpleGasPolicy.getGasUsed(configId, address(smartSession), instance.account), 0);
    }
}