import { IModule as IERC7579Module } from "erc7579/interfaces/IERC7579Module.sol";

library TrustedForwardLib {
    error TrustedForwarderCallFailed();

    function fwdCall(
        address target,
        bytes memory callData,
        address forAccount
    )
        internal
        returns (bytes memory returnData)
    {
        bool success;
        (success, returnData) = target.call(abi.encodePacked(callData, address(this), forAccount));
        if (!success) revert();
    }

    function onInstall(address subModule, address account, bytes32 id, bytes memory initData) internal {
        // abi.encodeWithSelector(ITrustedForwarder.setTrustedForwarder.selector, address(this), id)
        fwdCall(subModule, abi.encodeCall(IERC7579Module.onInstall, (initData)), account);
    }
}
