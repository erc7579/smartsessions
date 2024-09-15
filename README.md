> **This a minimal fork of the [erc7579/smartsessions repo](https://github.com/erc7579/smartsessions) used by Stackup's application layer. For the complete diff, [see here](https://github.com/erc7579/smartsessions/compare/main...stackup-wallet:smartsessions:accessctl).**

# SmartSession

SmartSession is an advanced module for ERC-7579 compatible smart accounts, enabling granular control over session keys. It allows users to create and manage temporary, limited-permission access to their accounts through configurable policies.

## Overview

SmartSession is a collaborative effort between Rhinestone and Biconomy to create a powerful and flexible session key management system for ERC-7579 accounts. It offers a comprehensive solution for secure, temporary account access in the evolving landscape of account abstraction.

## Features

- Granular control over session keys
- Support for various policy types:
  - User operation validation
  - Action-specific policies
  - ERC-1271 signature validation
- Unique "enable flow" for creating session keys within the first user operation
- Nested EIP-712 approach for EIP-1271 signature validation
- Native Support for ERC-7579 batched executions
- Integration with external policy contracts for flexible permission management

## Key Components

1. `SmartSession`: The main contract implementing the session key management system.
2. `SmartSessionBase`: Base contract containing core functionality.
3. `SmartSessionERC7739`: Mixin contract for ERC-1271 compatibility with nested EIP-712 approach.
4. `ISmartSession`: Interface defining the main functions and events for SmartSession.

## Usage

To use SmartSession in your ERC-7579 compatible smart account:

1. Deploy the SmartSession contract.
2. Install the SmartSession module on your smart contract wallet.
3. Create and configure sessions with desired policies and permissions.
4. Use the session keys to perform limited operations on the smart contract wallet.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the AGPL-3.0 License.

## Disclaimer

This software is in beta and should be used at your own risk. The authors are not responsible for any loss of funds or other damages that may occur from using this software.

## Authors

Filipp Makarov (Biconomy)
zeroknots.eth (Rhinestone)
