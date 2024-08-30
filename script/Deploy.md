## Deploy with Foundry Script

1. compile the cosigner with a FOUNDRY_PROFILE that uses via-ir

```bash
FOUNDRY_PROFILE=cosigner forge build
```

2. deploy components

```bash
export PRIVATE_KEY=0x...
forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast
```
