# Candide Labs Social Recovery Module

This package contains a social recovery module compatible with the Safe smart account. It was developed by Candide Labs, and subsequently formally verified by Safe. For additional documentation, full source code, and formal verification specification, see the [Candide Labs contracts](https://github.com/candidelabs/candide-contracts) repository.

The Safe team maintains a snapshot of the code that was evaluated at [safe-fndn/candide-contracts](https://github.com/safe-fndn/candide-contracts/tree/113d3c059e039e332637e8f686d9cbd505f1e738).

## External Contributions

Development of this module is done by the Candide Labs teams, and this package only re-exports the contracts and contains scripts to deterministically deploy. As such, please engage with the developers directly in the [candidelabs/candide-contracts](https://github.com/candidelabs/candide-contracts) repository, as we do not accept external contributions to the contracts here.

## Usage

### Install Requirements With PNPM:

```bash
pnpm install
```

## Deployments

A collection of the different deployments and their addresses can be found in the [Safe module deployments](https://github.com/safe-global/safe-modules-deployments) repository.

To add support for a new network follow the steps of the Deploy section and create a PR in the [Safe module deployments](https://github.com/safe-global/safe-modules-deployments) repository.

### Deploy

> :warning: **Make sure to use the correct commit when deploying the contracts.** Any change (even comments) within the contract files will result in different addresses. The tagged versions used by the Safe team can be found in the [releases](https://github.com/safe-global/safe-modules/releases).

This will deploy the contracts deterministically and verify the contracts on etherscan and sourcify.

Preparation:

- Set `MNEMONIC` in `.env`
- Set `INFURA_KEY` in `.env`

```bash
pnpm run deploy-all $NETWORK
```

This will perform the following steps

```bash
pnpm run build
npx hardhat --network $NETWORK deploy
npx hardhat --network $NETWORK local-verify
npx hardhat --network $NETWORK etherscan-verify
npx hardhat --network $NETWORK sourcify
```

### Compiler settings

The project uses Solidity compiler version `0.8.20` with 1 million optimizer runs using the IR optimizer.

### Custom Networks

It is possible to use the `NODE_URL` env var to connect to any EVM-based network via an RPC endpoint. This connection can then be used with the `custom` network.

E.g. to deploy the Safe contract suite on that network, you would run:

```bash
pnpm run deploy-all custom
```

The resulting addresses should be on all networks the same.

### Custom Recovery Period

By default this module uses a recovery period of 14 days. However, instances of this modules with other recovery periods can be deployed:

```bash
DEPLOYMENT_RECOVERY_PERIOD=... pnpm run deploy-all $NETWORK
```

> Note: The address is expected to be different for modules deployed this way.

## Documentation

- [Safe developer portal](http://docs.safe.global)
- [Candide account recovery](https://docs.candide.dev/wallet/plugins/recovery-with-guardians/)

## Audits

- [For version 0.1.0 by Ackee Blockchain](docs/v0.1.0/audit.md)

## Security and Liability

All contracts are WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

## License

All smart contracts are released under GPL-3.0.
