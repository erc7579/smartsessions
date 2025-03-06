import "../../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/IdLib.sol";
import "../base/PolicyTestBase.t.sol";
import { ContractWhitelistPolicy } from "contracts/external/policies/ContractWhitelistPolicy.sol";
import { MockPolicy } from "test/mock/MockPolicy.sol";

contract ContractWhitelistPolicyTest is PolicyTestBase {
    using IdLib for *;
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    event FallbackEvent(bytes4 sig);

    PermissionId permissionId_contractWhitelistAction;

    ContractWhitelistPolicy contractWhitelistPolicy;

    bytes contractWhitelistPolicyInitData;
    address[] targets;

    function setUp() public virtual override {
        super.setUp();

        contractWhitelistPolicy = new ContractWhitelistPolicy();

        targets.push(_target);
        contractWhitelistPolicyInitData = abi.encodePacked(_target);

        for (uint256 i = 1; i < 10; i++) {
            address newTarget = address(new MockTarget());
            targets.push(newTarget);
            contractWhitelistPolicyInitData = abi.encodePacked(contractWhitelistPolicyInitData, newTarget);
        }

        permissionId_contractWhitelistAction = _enableFallbackActionSession(
            address(contractWhitelistPolicy), contractWhitelistPolicyInitData, instance, keccak256("salt and pepper")
        );
    }

    function test_contractWhitelist_policy_init_reinit_use() public {
        PermissionId permissionId = use_contractWhitelist_policy_success();
        //permissionId = use_contractWhitelist_policy_fail(permissionId);
        reinit_contractWhitelist_policy(permissionId);
    }

    function test_contractWhitelist_policy_init_fails_with_invalid_init_data()
        public
        returns (PermissionId permissionId)
    {
        bytes memory invalidInitData = abi.encodePacked(uint256(0));
        vm.expectRevert(abi.encodeWithSelector(ContractWhitelistPolicy.InvalidInitData.selector));
        _enableFallbackActionSession(address(contractWhitelistPolicy), invalidInitData, instance, keccak256("salt"));

        invalidInitData = abi.encodePacked(targets[0], uint32(123_123));
        vm.expectRevert(abi.encodeWithSelector(ContractWhitelistPolicy.InvalidInitData.selector));
        _enableFallbackActionSession(address(contractWhitelistPolicy), invalidInitData, instance, keccak256("salt"));

        invalidInitData = abi.encodePacked(targets[0], targets[1], address(0), targets[2]);
        vm.expectRevert(abi.encodeWithSelector(ContractWhitelistPolicy.InvalidInitData.selector));
        _enableFallbackActionSession(address(contractWhitelistPolicy), invalidInitData, instance, keccak256("salt"));
    }

    function use_contractWhitelist_policy_success() public returns (PermissionId) {
        PermissionId permissionId = _enableFallbackActionSession(
            address(contractWhitelistPolicy), contractWhitelistPolicyInitData, instance, keccak256("salt")
        );

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (1337));
        // get userOp from ModuleKit
        UserOpData memory userOpData =
            instance.getExecOps({ target: _target, value: 0, callData: callData, txValidator: address(smartSession) });

        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });

        // execute userOp with modulekit
        userOpData.execUserOps();
        assertEq(target.value(), 1337);
        return permissionId;
    }

    function reinit_contractWhitelist_policy(PermissionId permissionId) public {
        address newTarget = address(new MockTarget());
        targets.push(newTarget);
        bytes memory newContractWhitelistPolicyInitData = abi.encodePacked(contractWhitelistPolicyInitData, newTarget);
        PermissionId permissionIdReInited = _enableFallbackActionSession(
            address(contractWhitelistPolicy), newContractWhitelistPolicyInitData, instance, keccak256("salt")
        );
        assertEq(PermissionId.unwrap(permissionIdReInited), PermissionId.unwrap(permissionId));

        bool isWhitelisted;

        for (uint256 i; i < targets.length; i++) {
            isWhitelisted = contractWhitelistPolicy.isContractWhitelisted(
                IdLib.toConfigId({
                    permissionId: permissionIdReInited,
                    actionId: FALLBACK_ACTIONID,
                    account: instance.account
                }),
                address(smartSession),
                instance.account,
                targets[i]
            );
            assertTrue(isWhitelisted);
        }
    }

    //test as action policy
    function test_use_contractWhitelist_policy_as_Fallback_policy_success(uint256 seed)
        public
        returns (PermissionId permissionId)
    {
        // remove last target from targets as it was not enabled in the setUp()
        targets.pop();

        bytes4 randomSelector = bytes4(keccak256(abi.encodePacked(seed)));
        for (uint256 i; i < targets.length; i++) {
            address currentTarget = targets[i];
            bytes memory callData = abi.encodeWithSelector(randomSelector);
            UserOpData memory userOpData = instance.getExecOps({
                target: currentTarget,
                value: 0,
                callData: callData,
                txValidator: address(smartSession)
            });
            userOpData.userOp.signature =
                EncodeLib.encodeUse({ permissionId: permissionId_contractWhitelistAction, sig: hex"4141414141" });
            vm.expectEmit(true, true, true, true, currentTarget);
            emit FallbackEvent(randomSelector);
            userOpData.execUserOps();
        }
    }

    function test_use_contractWhitelist_policy_fail() public {
        uint256 valueToSet = 1338;
        address noWhitelistedTarget = address(new MockTarget());
        uint256 targetValueBefore = MockTarget(noWhitelistedTarget).value();

        bytes memory callData = abi.encodeCall(MockTarget.setValue, (valueToSet));
        UserOpData memory userOpData = instance.getExecOps({
            target: noWhitelistedTarget,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature =
            EncodeLib.encodeUse({ permissionId: permissionId_contractWhitelistAction, sig: hex"4141414141" });

        bytes memory expectedRevertReason = abi.encodeWithSelector(
            IEntryPoint.FailedOpWithRevert.selector,
            0,
            "AA23 reverted",
            abi.encodeWithSelector(
                ISmartSession.PolicyViolation.selector,
                permissionId_contractWhitelistAction,
                address(contractWhitelistPolicy)
            )
        );

        // this should revert as the limit has been reached
        vm.expectRevert(expectedRevertReason);
        userOpData.execUserOps();
        assertEq(MockTarget(noWhitelistedTarget).value(), targetValueBefore);
    }

    function test_use_contractWhitelist_policy_as_fallback_and_other_policy_success(uint256 seed) public {
        MockPolicy mockPolicy = new MockPolicy();
        mockPolicy.setValidationData(0);
        PermissionId permissionId = _enable_Action_and_FallbackActionSession(
            address(contractWhitelistPolicy), address(mockPolicy), contractWhitelistPolicyInitData, abi.encodePacked(),
            instance, keccak256("salt")
        );

        uint256 valueBefore = MockTarget(_target).value();
        uint256 valueToSet = valueBefore + 1;

        // mockPolicy should be used for target.setValue
        bytes memory callData = abi.encodeWithSelector(MockTarget.setValue.selector, valueToSet);
        UserOpData memory userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        userOpData.execUserOps();
        assertEq(MockTarget(_target).value(), valueToSet);
        uint256 actionState = mockPolicy.actionState(
            IdLib.toConfigId({
                permissionId: permissionId,
                actionId: IdLib.toActionId(_target, MockTarget.setValue.selector),
                account: instance.account
            }),
            address(smartSession),
            instance.account
        );
        assertEq(actionState, 1);

        // contractWhitelistPolicy should be used for other methods
        bytes4 randomSelector = bytes4(keccak256(abi.encodePacked(seed)));
        callData = abi.encodeWithSelector(randomSelector);
        userOpData = instance.getExecOps({
            target: _target,
            value: 0,
            callData: callData,
            txValidator: address(smartSession)
        });
        userOpData.userOp.signature = EncodeLib.encodeUse({ permissionId: permissionId, sig: hex"4141414141" });
        vm.expectEmit(true, true, true, true, _target);
        emit FallbackEvent(randomSelector);
        userOpData.execUserOps();
    }
}
