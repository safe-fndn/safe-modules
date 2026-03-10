# Changelog

# Current Version

## Compiler settings

Solidity compiler: [0.8.26](https://github.com/ethereum/solidity/releases/tag/v0.8.26)

Solidity optimizer: enabled with 10.000.000 runs (via IR for all contracts)
EVM target: Paris

## Expected addresses

Same address as 0.2.1 release for all contracts, only the FCL contracts were removed.

## Changes

### General

- Remove the `FCLP256Verifier` contract and all related code, as it has some known bugs (nothing security critical ATM).

# Version 0.2.1

## Compiler settings

Solidity compiler: [0.8.26](https://github.com/ethereum/solidity/releases/tag/v0.8.26)

Solidity optimizer: enabled with 10.000.000 runs (via IR for all contracts except `FCLP256Verifier`)
EVM target: Paris

## Expected addresses

- `SafeWebAuthnSignerFactory` at `0x1d31F259eE307358a26dFb23EB365939E8641195`
- `SafeWebAuthnSharedSigner` at `0x94a4F6affBd8975951142c3999aEAB7ecee555c2`
- `DaimoP256Verifier` at `0xc2b78104907F722DABAc4C69f826a522B2754De4` ([source](https://p256.eth.limo/))
- `FCLP256Verifier` at `0xA86e0054C51E4894D88762a017ECc5E5235f5DBA`

## Changes

### Security Fixes

- Check the success of the static call to the SHA-256 precompile.

### General

- Using the [`safe-singleton-factory`](https://github.com/safe-global/safe-singleton-factory) to deploy contracts.
- Use compiler version 0.8.26 and use IR optimizer for all contracts (except `FCLP256Verifier` as it introduces perfomance regressions). This simultaneously decreases code size and runtime gas costs.
- Index the `signer` field for `Created` event in the `SafeWebAuthnSignerFactory` contract.
- Use more consistent compiler version pragmas throughout the contracts.
- Initial release of the `SafeWebAuthnSharedSigner` contract.

# Version 0.2.0

## Compiler settings

Solidity compiler: [0.8.24](https://github.com/ethereum/solidity/releases/tag/v0.8.24)

Solidity optimizer: enabled with 10.000.000 runs
EVM target: Paris

## Expected addresses

- `SafeWebAuthnSignerFactory` at `0xF7488fFbe67327ac9f37D5F722d83Fc900852Fbf`
- `DaimoP256Verifier` at `0xc2b78104907F722DABAc4C69f826a522B2754De4`
- `FCLP256Verifier` at `0x445a0683e494ea0c5AF3E83c5159fBE47Cf9e765`

## Changes

### General

- First release of the passkey contracts.
