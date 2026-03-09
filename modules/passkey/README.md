# Passkey

This package contains a passkey signature verifier, that can be used as an owner for a Safe, compatible with versions 1.3.0+.

Passkey support with the Safe is provided by implementing [`SignatureValidator`s](./contracts/base/SignatureValidator.sol) that can verify WebAuthn signatures on-chain, the underlying standard used by passkeys, and be used as owners for Safe accounts. At a high level, this works by:

1. Deploying a signer instance using the [SafeWebAuthnSignerFactory](./contracts/SafeWebAuthnSignerFactory.sol), this will create a contract instance at a deterministic address using `CREATE2` based the parameters of the WebAuthn credential: the public key coordinates and which `ecverify` implementations to use.
2. Set the deployed signer as an owner for a Safe.

## Contracts Overview

Safe account being standard agnostic, new user flows such as custom signature verification logic can be added/removed as and when required. By leveraging this flexibility to support customizing Safe account, Passkeys-based execution flow can be enabled on a Safe. The contracts in this package use [ERC-1271](https://eips.ethereum.org/EIPS/eip-1271) standard and [WebAuthn](https://w3c.github.io/webauthn/) standard to allow signature verification for WebAuthn credentials using the secp256r1 curve. The contracts in this package are designed to be used with precompiles for signature verification in the supported networks or use any verifier contract implementing the EIP-7212 interface as a fallback mechanism. In their current state, the contracts are tested with [Daimo P-256 verifier](https://github.com/daimo-eth/p256-verifier).

The below sections give a high-level overview of the contracts present in this package.

### [SafeWebAuthnSignerProxy](./contracts/SafeWebAuthnSignerProxy.sol)

A proxy contract is uniquely deployed for each Passkey signer. The signer information i.e, Public key co-ordinates, Verifier address, Singleton address are immutable. All calls to the signer are forwarded to the `SafeWebAuthnSignerSingleton` contract.

Use of `SafeWebAuthnSignerProxy` provides gas savings compared to the whole contract deployment for each signer creation. Both `SafeWebAuthnSignerProxy` and `SafeWebAuthnSignerSingleton` use no storage slots to avoid storage access violations defined in ERC-4337. The details on gas savings can be found in [this PR](https://github.com/safe-global/safe-modules/pull/370). This non-standard proxy contract appends signer information i.e., public key co-ordinates, and verifier data to the calldata before forwarding call to the singleton contract.

### [SafeWebAuthnSignerSingleton](./contracts/SafeWebAuthnSignerSingleton.sol)

`SafeWebAuthnSignerSingleton` contract is a singleton contract that implements the ERC-1271 interface to support signature verification, enabling signature data to be forwarded from a Safe to the `WebAuthn` library. This contract expects public key co-ordinates, and verifier address to be appended by the caller inspired from [ERC-2771](https://eips.ethereum.org/EIPS/eip-2771).

### [SafeWebAuthnSignerFactory](./contracts/SafeWebAuthnSignerFactory.sol)

The `SafeWebAuthnSignerFactory` contract deploys the `SafeWebAuthnSignerProxy` contract with the public key coordinates and verifier information. The factory contract also supports signature verification for the public key and signature information without deploying the signer contract. Using [ISafeSignerFactory](./contracts/interfaces/ISafeSignerFactory.sol) interface and this factory contract address, new signers can be deployed.

### [WebAuthn](./contracts/libraries/WebAuthn.sol)

This library is used for generating signing message, hashing it and forwarding the call to the verifier contract. The `WebAuthn` library defines `Signature` struct containing `authenticatorData`, `clientDataFields`, followed by ECDSA signature's `r` and `s` components. The `authenticatorData` and `clientDataFields` required for generating the signing message. The `bytes` signature received in `verifySignature(...)` function is cast to `Signature` struct so, the caller has to take into account formatting the signature bytes as expected by the `WebAuthn` library.

The below code snippet shows signature encoding for verification using `WebAuthn` library.

```solidity
bytes authenticatorData = ...;
string clientDataFields = ...;
uint256 r = ...;
uint256 s = ...;
// Encode the signature data
bytes memory signature = abi.encode(authenticatorData, clientDataFields, r, s);
```

### [P256](./contracts/libraries/P256.sol)

`P256` is a library for P256 signature verification with contracts that follows the EIP-7212 EC verify precompile interface. This library defines a custom type `Verifiers`, which encodes two addresses into a single `uint176`. The first address (2 bytes) is a precompile address dedicated to verification, and the second (20 bytes) is a fallback address. This setup allows the library to support networks where the precompile is not yet available, seamlessly transitioning to the precompile when it becomes active, while relying on a fallback contract address in the meantime. Note that only 2 bytes are needed to represent the precompile address, as the reserved range for precompile contracts is between address 0x0000 and 0xffff which fits into 2 bytes.

The `verifiers` value can be computed with the following code:

```solidity
uint16 precompile = ...;
address fallbackVerifier = ...;

P256.Verifiers = P256.Verifiers.wrap(
    (uint176(precompile) << 160) + uint176(uint160(fallbackVerifier))
);
```

## Usage

### Install Requirements With NPM:

```bash
pnpm install
```

### Run Hardhat Tests:

```bash
pnpm test
pnpm run test:4337
```

## Deployments

### Deploy

> :warning: **Make sure to use the correct commit when deploying the contracts.** Any change (even comments) within the contract files will result in different addresses. The tagged versions used by the Safe team can be found in the [releases](https://github.com/safe-global/safe-modules/releases).

This will deploy the contracts deterministically and verify the contracts on etherscan and sourcify.

Preparation:

- Set `MNEMONIC` or `PK` in `.env`
- Set `ETHERSCAN_API_KEY` in `.env`

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
npx hardhat --network $NETWORK verify $SAFE_WEBAUTHN_SIGNER_SINGLETON_ADDRESS --contract SafeWebAuthnSignerSingleton
```

### Compiler settings

The project uses Solidity compiler version `0.8.26` with 10 million IR optimizer runs, as we want to optimize for the code execution costs. The EVM version is set to `paris` because not all our target networks support the opcodes introduced in the `Shanghai` EVM upgrade.

#### Custom Networks

It is possible to use the `NODE_URL` env var to connect to any EVM-based network via an RPC endpoint. This connection can then be used with the `custom` network.

E.g. to deploy the contract suite on that network, you would run `npm run deploy-all custom`.

The resulting addresses should be on all networks the same.

Note: The address will vary if the contract code changes or a different Solidity version is used.

### Run Benchmark Tests

```bash
pnpm run bench
```

### User Stories

The test cases in [userstories](./test/userstories) directory demonstrates the usage of the passkey module in different scenarios like deploying a Safe account with passkey module enabled, executing a `userOp` with a Safe using Passkey signer, etc.

## Audits

- [For version 0.2.0](docs/v0.2.0/audit.md)
- [For version 0.2.1](docs/v0.2.1/audit.md)

## Privacy

WebAuthn attestations include an [Authenticator Attestation Globally Unique Identifier or _**AAGUID**_](https://w3c.github.io/webauthn/#aaguid) which indicates the type (e.g. make and model) of the authenticator. Because this AAGUID is required for signature verification, it is published on-chain and can be used to determine the kind of authenticator that is being used by a given passkey Safe owner (for example, that you are using a passkey stored in an iCloud keychain, or a YubiKey 5, to control your Safe).

## Security and Liability

All contracts are WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

## License

All smart contracts are released under LGPL-3.0.
