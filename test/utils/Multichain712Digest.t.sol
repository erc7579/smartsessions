import "../Base.t.sol";
import "contracts/core/SmartSessionBase.sol";
import "solady/utils/ECDSA.sol";
import "contracts/lib/HashLib.sol";

contract Multichain712DigestTest is BaseTest {
    using ModuleKitHelpers for *;
    using ModuleKitUserOp for *;
    using EncodeLib for *;
    using HashLib for *;
    using TestHashLib for *;

    function setUp() public virtual override {
        super.setUp();
    }

    function test_multichain_digest_creation() public {
        Session memory session = Session({
            sessionValidator: ISessionValidator(address(yesSessionValidator)),
            salt: keccak256("salt"),
            sessionValidatorInitData: "mockInitData",
            userOpPolicies: _getEmptyPolicyDatas(address(yesPolicy)),
            erc7739Policies: _getEmptyERC7739Data("mockContent", _getEmptyPolicyDatas(address(yesPolicy))),
            actions: _getEmptyActionDatas(makeAddr("target"), bytes4(0x41414141), address(yesPolicy))
        });

        // Make sessionsAndChainIds
        uint64[] memory chainIds = new uint64[](3);
        chainIds[0] = 1855;
        chainIds[1] = uint64(block.chainid);
        chainIds[2] = 181_818;
        uint256[] memory nonces = new uint256[](3);
        nonces[0] = smartSession.getNonce(smartSession.getPermissionId(session), instance.account);
        nonces[1] = nonces[0];
        nonces[2] = nonces[0];
        SmartSessionMode[] memory modes = new SmartSessionMode[](3);
        modes[0] = SmartSessionMode.UNSAFE_ENABLE;
        modes[1] = SmartSessionMode.UNSAFE_ENABLE;
        modes[2] = SmartSessionMode.UNSAFE_ENABLE;
        address[] memory accounts = Solarray.addresses(instance.account, instance.account, instance.account);
        address[] memory smartSessions =
            Solarray.addresses(address(smartSession), address(smartSession), address(smartSession));

        ChainSession[] memory sessionsAndChainIds = new ChainSession[](3);
        ChainDigest[] memory hashesAndChainIds = new ChainDigest[](3);

        for (uint256 i = 0; i < 3; i++) {
            ChainSession memory chainSession = ChainSession({ chainId: chainIds[i], session: session });
            sessionsAndChainIds[i] = chainSession;

            // that's how signTypedData will be hashing
            bytes32 digest = session._sessionDigest({
                account: accounts[i],
                smartSession: smartSessions[i],
                mode: modes[i],
                nonce: nonces[i]
            });
            ChainDigest memory chainDigest = ChainDigest({ chainId: chainIds[i], sessionDigest: digest });
            hashesAndChainIds[i] = chainDigest;
        }

        MultiChainSession memory multiChainSession = MultiChainSession({ sessionsAndChainIds: sessionsAndChainIds });

        bytes32 fullHash = multiChainSession.multichainDigest(accounts, smartSessions, modes, nonces);
        bytes32 mimicHash = hashesAndChainIds.multichainDigest();

        assertEq(fullHash, mimicHash);
    }
}
