interface ITrustedForwarder {
    function isTrustedForwarder(address forwarder, address account, bytes32 id) external returns (bool);

    function setTrustedForwarder(address forwarder, bytes32) external;
}
