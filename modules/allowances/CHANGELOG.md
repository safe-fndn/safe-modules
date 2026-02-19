# Changelog

This changelog only contains changes starting from version 0.1.1

# Version 1.0.0

## Compiler settings

Solidity compiler: [0.7.6](https://github.com/ethereum/solidity/releases/tag/v0.7.6)

Solidity optimizer: disabled

## Expected addresses

- `AllowanceModule` at `TBD`

## Changes

### Security

#### Prevent Nonce Overflow in Allowance Module

Pull request: [#520](https://github.com/safe-fndn/safe-modules/pull/520)

Fixes a nonce overflow that would potentially allow replaying past allowance module transfers.

#### Revert on Failed Token Transfer

Issue: [#237](https://github.com/safe-fndn/safe-modules/issues/237)

Fixes an issue where the allowance would not revert as expected for ERC-20 token transfers that returned `false` instead of reverting, which is allowed by the ERC-20 standard (albeit discouraged). This would cause a delegate's allowance data to be updated despite the transfer failing.

Note that this fix requires additional Safe features introduced in v1.1.1+ and **breaks compatibility with Safe v1.0.0**.

### General

#### Prevent Delegate Deletion on Key Collision

Pull request: [#523](https://github.com/safe-fndn/safe-modules/pull/523)

Fixes the `removeDelegate` to revert in case of key collision, instead of removing the wrong delegate and leaving orphaned allowances.

#### Add Missing NatSpec Documentation

Pull request: [#525](https://github.com/safe-fndn/safe-modules/pull/525)

Add missing NatSpec documentation to the allowance module contract, improving overall documentation for the contracts.

# Version 0.1.1

## Compiler settings

Solidity compiler: [0.7.6](https://github.com/ethereum/solidity/releases/tag/v0.7.6)

Solidity optimizer: disabled

## Expected addresses

- `AllowanceModule` at `0xAA46724893dedD72658219405185Fb0Fc91e091C`

## Changes

### General

#### Fix the EIP-712 transfer typehash

Issue: [#70](https://github.com/safe-global/safe-modules/issues/70)

The typehash for the transfer was incorrect, making it impossible to use the module with EIP-712 signatures.

#### Add a check for `resetTimeMin` 

For recurring allowances, the `resetTimeMin` must be greater than 0. However, the check was missing, making it possible to specify a `resetTimeMin` of 0, resulting in a divide by zero error and the transaction consuming all gas.

The change was suggested by the [Ackee blockchain](https://ackee.xyz/) during the audit of the module.
