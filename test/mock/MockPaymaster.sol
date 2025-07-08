import "@ERC4337/account-abstraction/contracts/core/BasePaymaster.sol";
import "@ERC4337/account-abstraction/contracts/core/Helpers.sol";
import "@ERC4337/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MockPaymaster is BasePaymaster {
    constructor(IEntryPoint _entryPoint) BasePaymaster(_entryPoint) { }

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    )
        internal
        virtual
        override
        returns (bytes memory context, uint256 validationData)
    {
        context = "";
        validationData = _packValidationData(false, uint48(type(uint48).max), uint48(0));
    }
}
