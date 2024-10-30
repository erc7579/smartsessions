import "forge-std/Test.sol";
import "contracts/lib/HashLib.sol";
import "contracts/DataTypes.sol";

contract Helper {
    using HashLib for *;

    function hash(Session memory session) public returns (bytes32 hash) {
        hash = session.sessionDigest({
            account: address(0x6605F8785E09a245DD558e55F9A0f4A508434503),
            mode: SmartSessionMode.ENABLE,
            nonce: 0
        });
    }
}

bytes32 constant APP_DOMAIN_SEPARATOR = keccak256("0x01");

contract EIP712Test is Test {
    using HashLib for *;

    Helper helper;

    function setUp() public {
        helper = new Helper();
        address helperAddr = address(0x6605F8785E09a245DD558e55F9A0f4A508434503);
        vm.etch(helperAddr, address(helper).code);
        helper = Helper(helperAddr);
    }

    // function test_type_notation() public {
    //     // test multichain hash
    //     string memory expectedMultiChainSessionTypeHash =
    //         "MultiChainSessionEIP712(ChainSessionEIP712[] sessionsAndChainIds)ActionData(bytes4
    // actionTargetSelector,address actionTarget,PolicyData[] actionPolicies)ChainSessionEIP712(uint64
    // chainId,SessionEIP712 session)ERC7739Data(string[] allowedERC7739Content,PolicyData[]
    // erc1271Policies)PolicyData(address policy,bytes initData)SessionEIP712(address account,address smartSession,uint8
    // mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data
    // erc7739Policies,ActionData[] actions,uint256 nonce)";
    //     bytes32 hash = keccak256(abi.encodePacked(expectedMultiChainSessionTypeHash));
    //     assertEq(hash, MULTICHAIN_SESSION_TYPEHASH);
    //
    //     string memory expectedChainSession =
    //         "ChainSessionEIP712(uint64 chainId,SessionEIP712 session)ActionData(bytes4 actionTargetSelector,address
    // actionTarget,PolicyData[] actionPolicies)ERC7739Data(string[] allowedERC7739Content,PolicyData[]
    // erc1271Policies)PolicyData(address policy,bytes initData)SessionEIP712(address account,address smartSession,uint8
    // mode,address sessionValidator,bytes32 salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data
    // erc7739Policies,ActionData[] actions,uint256 nonce)";
    //     hash = keccak256(abi.encodePacked(expectedChainSession));
    //     assertEq(hash, CHAIN_SESSION_TYPEHASH);
    //
    //     string memory expectedSession =
    //         "SessionEIP712(address account,address smartSession,uint8 mode,address sessionValidator,bytes32
    // salt,bytes sessionValidatorInitData,PolicyData[] userOpPolicies,ERC7739Data erc7739Policies,ActionData[]
    // actions,uint256 nonce)ActionData(bytes4 actionTargetSelector,address actionTarget,PolicyData[]
    // actionPolicies)ERC7739Data(string[] allowedERC7739Content,PolicyData[] erc1271Policies)PolicyData(address
    // policy,bytes initData)";
    //     hash = keccak256(abi.encodePacked(expectedSession));
    //     assertEq(hash, SESSION_TYPEHASH);
    // }

    function test_policy_hash() public {
        bytes32 expected_typehash = 0xdddac12cd8b10a071bea04226e97ac9490698394e19224abc47a5cfeeeb6ee97;
        assertEq(expected_typehash, POLICY_DATA_TYPEHASH);

        PolicyData memory policyData =
            PolicyData({ policy: address(0xf022051bEB9E8848e99f47D3eD1397CEEfBF3d4F), initData: "" });

        bytes32 hash = policyData.hashPolicyData();
        bytes32 expected_hash = 0x531c8f7eafebd3a565ad77225700ee7551c4c552b8e8a8417710ec2aa7990e9d;
        assertEq(hash, expected_hash);

        console2.logBytes(abi.encode(policyData));
    }

    function test_action_hash() public {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(0xf022051bEB9E8848e99f47D3eD1397CEEfBF3d4F), initData: "" });

        ActionData memory actionData = ActionData({
            actionTarget: address(0x7227DCfB0c5EC7A5F539F97b18Be261C49687eD6),
            actionTargetSelector: bytes4(0x9cfd7cff),
            actionPolicies: policyDatas
        });

        bytes32 expected_typehash = 0x35809859dccf8877c407a59527c2f00fb81ca9c198ebcb0c832c3deaa38d3502;
        assertEq(expected_typehash, ACTION_DATA_TYPEHASH);
        bytes32 hash = actionData.hashActionData();
        bytes32 expected_hash = 0xe7fd3595c8793c559219f8cfb42f912d7e5f196fdc8db29bbdb718127fbed2e4;

        assertEq(hash, expected_hash);
    }

    function test_erc7739_hash() public pure {
        ERC7739Context[] memory contexts = new ERC7739Context[](1);
        contexts[0].contentName = "mockContent";
        contexts[0].appDomainSeparator = EIP712Domain({
            name: "Forge",
            version: "1",
            chainId: 1,
            verifyingContract: address(0x6605F8785E09a245DD558e55F9A0f4A508434503)
        });

        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(0), initData: "" });

        ERC7739Data memory erc7739Data = ERC7739Data({ allowedERC7739Content: contexts, erc1271Policies: policyDatas });

        bytes32 contextHash = erc7739Data.allowedERC7739Content[0].hashERC7739Context();
        bytes32 expected_hash = 0x7bf774767fc9639d50b9b3d1d46dd5aca589488a95ae40673c815c46b4edda68;
        assertEq(contextHash, expected_hash);

        bytes32 hash = erc7739Data.hashERC7739Data();
        expected_hash = 0x18d338f81763ec82d67d0a21cb8d05c2efaba5896544ede55fcc8238d98c4a71;
        assertEq(hash, expected_hash);
    }

    function test_session_hash() public {
        PolicyData[] memory policyDatas = new PolicyData[](1);
        policyDatas[0] = PolicyData({ policy: address(0), initData: "" });

        ActionData[] memory actions = new ActionData[](1);
        actions[0] =
            ActionData({ actionTarget: address(0), actionTargetSelector: bytes4(0), actionPolicies: policyDatas });

        Session memory session = Session({
            sessionValidator: ISessionValidator(address(0)),
            sessionValidatorInitData: "",
            salt: bytes32(0),
            userOpPolicies: policyDatas,
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(0))),
            actions: actions
        });

        assertEq(
            session.userOpPolicies[0].hashPolicyData(),
            0x55d06d5dca0ed9e6953c38510f2069a0b5481deb9bb41b392301de5c636cfdfb,
            "policyData hashing"
        );
        assertEq(
            session.erc7739Policies.hashERC7739Data(),
            0x18d338f81763ec82d67d0a21cb8d05c2efaba5896544ede55fcc8238d98c4a71,
            "ERC7739Data hashing"
        );

        assertEq(
            session.actions[0].hashActionData(),
            0x907d2bb46edfac5e2e9e21d5b93225573f78d6a79be8f54c16d5779e9a1c9102,
            "action data hashing"
        );

        console2.log("helper addr:", address(helper));

        bytes32 expectedSessionHash = 0x13b36e5c011a5a4fe095b82d73148a84b3f5b258f81184e23b644f65f5370a1e;

        bytes32 hash = helper.hash(session);
        // bytes32 expected_hash = 0x4e1b5958b515b1750b96d520eccbb89236e76222301abc68a037111e2efa6687;
        assertEq(hash, expectedSessionHash, "hash fn borked");
    }

    function _getEmptyERC7739Data(
        string memory content,
        PolicyData[] memory erc1271Policies
    )
        internal
        returns (ERC7739Data memory)
    {
        ERC7739Context[] memory contents = new ERC7739Context[](1);
        contents[0].contentName = content;
        contents[0].appDomainSeparator = EIP712Domain({
            name: "Forge",
            version: "1",
            chainId: 1,
            verifyingContract: address(0x6605F8785E09a245DD558e55F9A0f4A508434503)
        });
        return ERC7739Data({ allowedERC7739Content: contents, erc1271Policies: erc1271Policies });
    }

    function _getEmptyPolicyData(address policyContract) internal pure returns (PolicyData memory) {
        return PolicyData({ policy: policyContract, initData: "" });
    }

    function _getEmptyPolicyDatas(address policyContract) internal pure returns (PolicyData[] memory policyDatas) {
        policyDatas = new PolicyData[](1);
        policyDatas[0] = _getEmptyPolicyData(policyContract);
    }
}
