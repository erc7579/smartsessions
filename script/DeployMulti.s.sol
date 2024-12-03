import "./DeployScript.s.sol";
import "forge-std/console2.sol";

contract DeployMulti is DeploySmartSession {
    function run() public {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        console2.log("Deployer Addr: ", vm.addr(privKey));

        runFork("gnosis");
        // runFork("bsc-testnet");
        // runFork("polygon");
        // runFork("fuse");
        // runFork("fuse-spark");
        // runFork("celo");
        // runFork("celo-alfajores");
        // runFork("scroll");
        // runFork("scroll-sepolia");

        // runFork("optimism-sepolia");
        // runFork("polygon");
        // runFork("polygon-amoy");
        // runFork("sepolia");
        // runFork("base");
        // runFork("base-sepolia");
        // runFork("avalanche");
        // runFork("avalanche-fuji");
        // runFork("gnosis");
        // runFork("gnosis-chidao");
        // runFork("bsc-testnet");
        // runFork("bsc");
        // runFork("scroll-testnet");
        // runFork("scroll");
    }

    function runFork(string memory fork) internal {
        try this.tryRunFork(fork) { }
        catch (bytes memory error) {
            console2.log("Error running fork: ", fork);
        }
    }

    function tryRunFork(string memory fork) external {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        vm.createSelectFork(fork);
        deploy(privKey);
    }
}
