// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import { Test } from "forge-std/Test.sol";
import { Solarray } from "solarray/Solarray.sol";
import {
    RhinestoneModuleKit,
    ModuleKitHelpers,
    ModuleKitUserOp,
    AccountInstance,
    UserOpData
} from "modulekit/ModuleKit.sol";
import { MODULE_TYPE_VALIDATOR, MODULE_TYPE_EXECUTOR, Execution } from "modulekit/external/ERC7579.sol";
import { SmartSession } from "contracts/SmartSession.sol";
import { EncodeLib } from "contracts/lib/EncodeLib.sol";
import { ISessionValidator } from "contracts/interfaces/ISessionValidator.sol";
import { IRegistry } from "contracts/interfaces/IRegistry.sol";
import "contracts/DataTypes.sol";
import { EncodeLib } from "contracts/lib/EncodeLib.sol";
import { YesSessionValidator } from "./mock/YesSessionValidator.sol";
import { MockTarget } from "./mock/MockTarget.sol";
import { YesPolicy } from "./mock/YesPolicy.sol";
import { SudoPolicy } from "contracts/external/policies/SudoPolicy.sol";
import { MockRegistry } from "./mock/MockRegistry.sol";
import { SimpleSessionValidator } from "./mock/SimpleSessionValidator.sol";
import { SimpleGasPolicy } from "./mock/SimpleGasPolicy.sol";
import { TimeFramePolicy } from "./mock/TimeFramePolicy.sol";
import { ValueLimitPolicy } from "./mock/ValueLimitPolicy.sol";
import { UsageLimitPolicy } from "./mock/UsageLimitPolicy.sol";
import { EIP1271_MAGIC_VALUE, IERC1271 } from "module-bases/interfaces/IERC1271.sol";
import { MockK1Validator } from "test/mock/MockK1Validator.sol";
import { UserOperationBuilder } from "test/mock/erc7679/UserOpBuilder.sol";
import { ModeLib, ModeCode as ExecutionMode } from "erc7579/lib/ModeLib.sol";
import { HashLib } from "contracts/lib/HashLib.sol";
import { TestHashLib } from "test/utils/lib/TestHashLib.sol";
import { IntegrationEncodeLib } from "test/utils/lib/IntegrationEncodeLib.sol";
import { IEntryPoint } from "account-abstraction/interfaces/IEntryPoint.sol";

import "forge-std/console2.sol";

contract BaseTest is RhinestoneModuleKit, Test {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for PermissionId;

    // account and modules
    MockK1Validator internal mockK1;
    AccountInstance internal instance;
    SmartSession internal smartSession;
    YesPolicy internal yesPolicy;
    SudoPolicy internal sudoPolicy;
    YesSessionValidator internal yesSessionValidator;
    SimpleSessionValidator internal simpleSessionValidator;
    SimpleGasPolicy internal simpleGasPolicy;
    TimeFramePolicy internal timeFramePolicy;
    ValueLimitPolicy internal valueLimitPolicy;
    UsageLimitPolicy internal usageLimitPolicy;

    MockTarget target;
    Account sessionSigner1;
    Account sessionSigner2;
    Account owner;

    function setUp() public virtual {
        instance = makeAccountInstance("smartaccount");
        mockK1 = new MockK1Validator();

        IRegistry _registry = IRegistry(address(new MockRegistry()));
        vm.etch(address(registry), address(_registry).code);

        owner = makeAccount("owner");
        sessionSigner1 = makeAccount("sessionSigner1");
        sessionSigner2 = makeAccount("sessionSigner2");

        smartSession = new SmartSession();
        target = new MockTarget();
        yesSessionValidator = new YesSessionValidator();
        yesPolicy = new YesPolicy();
        sudoPolicy = new SudoPolicy();
        simpleSessionValidator = new SimpleSessionValidator();
        simpleGasPolicy = new SimpleGasPolicy();
        timeFramePolicy = new TimeFramePolicy();
        valueLimitPolicy = new ValueLimitPolicy();
        usageLimitPolicy = new UsageLimitPolicy();

        instance.installModule({
            moduleTypeId: MODULE_TYPE_VALIDATOR,
            module: address(mockK1),
            data: abi.encodePacked(owner.addr)
        });

        instance.installModule({ moduleTypeId: MODULE_TYPE_VALIDATOR, module: address(smartSession), data: "" });
    }

    function sign(bytes32 hash, uint256 privKey) internal pure returns (bytes memory signature) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey, hash);
        // Set the signature
        signature = abi.encodePacked(r, s, v);
    }

    function _getEmptyPolicyData(address policyContract) internal pure returns (PolicyData memory) {
        return PolicyData({ policy: policyContract, initData: "" });
    }

    function _getEmptyPolicyDatas(address policyContract) internal pure returns (PolicyData[] memory policyDatas) {
        policyDatas = new PolicyData[](1);
        policyDatas[0] = _getEmptyPolicyData(policyContract);
    }

    function _getEmptyActionData(
        address actionTarget,
        bytes4 actionSelector,
        address policyContract
    )
        internal
        pure
        returns (ActionData memory)
    {
        return ActionData({
            actionTargetSelector: actionSelector,
            actionTarget: actionTarget,
            actionPolicies: _getEmptyPolicyDatas(policyContract)
        });
    }

    function _getEmptyActionDatas(
        address actionTarget,
        bytes4 actionSelector,
        address policyContract
    )
        internal
        pure
        returns (ActionData[] memory actionDatas)
    {
        actionDatas = new ActionData[](1);
        actionDatas[0] = _getEmptyActionData(actionTarget, actionSelector, policyContract);
    }

    function _getEmptyERC7739Data(
        string memory content,
        PolicyData[] memory erc1271Policies
    )
        internal
        returns (ERC7739Data memory)
    {
        string[] memory contents = new string[](1);
        contents[0] = content;
        return ERC7739Data({ allowedERC7739Content: contents, erc1271Policies: erc1271Policies });
    }

    function _makeMultiChainEnableData(
        PermissionId permissionId,
        Session memory session,
        AccountInstance memory instance,
        SmartSessionMode mode
    )
        internal
        view
        returns (EnableSession memory enableData)
    {
        bytes32 sessionDigest = smartSession.getSessionDigest({
            permissionId: permissionId,
            account: instance.account,
            data: session,
            mode: mode
        });

        ChainDigest[] memory chainDigests = IntegrationEncodeLib.encodeHashesAndChainIds(
            Solarray.uint64s(181_818, uint64(block.chainid), 777),
            Solarray.bytes32s(sessionDigest, sessionDigest, sessionDigest)
        );

        enableData = EnableSession({
            chainDigestIndex: 1,
            hashesAndChainIds: chainDigests,
            sessionToEnable: session,
            permissionEnableSig: ""
        });
    }
}
