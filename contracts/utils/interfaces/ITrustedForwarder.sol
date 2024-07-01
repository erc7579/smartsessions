// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity ^0.8.23;

// import IERC165 from OpenZeppelin Contracts
import "@openzeppelin/contracts/utils/introspection/IERC165.sol";

interface ITrustedForwarder is IERC165 {
    // InterfaceId is 0x41f02a24

    function setTrustedForwarder(address forwarder, bytes32 id) external;

    function clearTrustedForwarder(bytes32 id) external;

    function isTrustedForwarder(address forwarder, address account, bytes32 id) external view returns (bool);
}
