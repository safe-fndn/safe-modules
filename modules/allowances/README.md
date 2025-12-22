# Allowance module

This contract is a registry of transfer allowances on a Safe that can be used by specific accounts. For this the contract needs to be enabled as a module on the Safe that holds the assets that should be transferred. The registry is written to be used with ERC20 tokens and Ether (represented by the zero address).

All transfer allowances are specific to a Safe, token and delegate. A delegate is an account that can authorize transfers (via a signature or `msg.sender`).

Note: This is not about allowances on an ERC20 token contract.

## Setting up allowances

The contract is designed as a single point registry. This way not every Safe needs to deploy their own module and it is possible that this module is shared between different Safes.

To set an allowance for a Safe it is first required that the Safe adds a **delegate**. For this a Safe transaction needs to be executed that calls `addDelegate`. This method will add the specified **delegate** for `msg.sender`, which is the Safe in case of a Safe transaction. The `addDelegate` method can be called multiple times with the same address for a **delegate** without failure.

Once a **delegate** has been enabled it is possible to set an allowance for that **delegate**. For this a Safe transaction needs to be executed that calls `setAllowance`.

To delete an allowance for a specific token a Safe transaction needs to be executed that calls `deleteAllowance`. Another way is to remove the **delegate** with a Safe transaction that calls `removeDelegate`, but this will remove all allowances for this delegate.

Note: calling `setAllowance` will not change the `spent` value of an allowance. To reset the `spent` value you need to call `resetAllowance`.

## Transfer authorization

Transfer are authorized by the delegates and must be within their allowance. To authorize a transfer the delegate must either generate a valid signature or be the `msg.sender` of the transaction. The allowance module uses the same [signature scheme as the Gnosis Safe](https://docs.safe.global/advanced/smart-account-signatures), except that the allowance module does not support contract signatures or approved hashes. Also if an empty signature is provided, or `v == 1`, the `msg.sender` is used instead.

The allowance module signatures are EIP-712 based. And uses the following scheme:

- EIP712Domain
```json
{
    "EIP712Domain": [
        { "type": "uint256", "name": "chainId" },
        { "type": "address", "name": "verifyingContract" }
    ]
}
``` 

- AllowanceTransfer
```json
{
    "AllowanceTransfer": [
        { "type": "address", "name": "safe" },
        { "type": "address", "name": "token" },
        { "type": "address", "name": "to" },
        { "type": "uint96", "name": "amount" },
        { "type": "address", "name": "paymentToken" },
        { "type": "uint96", "name": "payment" },
        { "type": "uint16", "name": "nonce" },
    ]
}
``` 

## Transfer execution

Anyone can execute the transfer as long as they provide the [transfer authorization](#transfer-authorization) of a valid **delegate**. To execute the transfer the `executeAllowanceTransfer` method needs to be called, that checks the signature and calls the Safe to perform the transfer.

When calling the Safe there are two cases that need to be differentiated: an Ether transfer, and a token transfer.
- In case of an **Ether transfer** the module instructs the Safe to transfer the specified amount to the receiver (so no data is provided).
- In case of a **token transfer** the module instructs the Safe to call the transfer method on the token contract to transfer the specified amount to the receiver (so a value of `0` is provided).

## One time allowances

If the `resetTimeMin` time of an allowance is `0` then the allowance will not automatically renew. This means when the `delegate` has used up the allowance it is necessary to "reset" the allowance by performing a Safe transaction that calls `resetAllowance`.

## Recurring allowances
If `resetTimeMin` is set to any value greater than `0` the allowance will automatically renew after the specified amount of minutes based on the last reset time. The initial reset time can be specified with `resetBaseMin`. This can be used to set the time of day the allowance is renewed.

Specifically this means that after the specified time the `spent` amount of an allowance will be reset to `0` and therefore the allowance can be used again until `spent` is greater than the allowance `amount`.

## Refund transfer execution

It is possible to define a refund that is paid to `tx.origin`. This refund is also subject to the allowance, so if the allowance is not high enough to pay for the refund the transaction will fail.

### Considerations

- Transactions can be front-run/ executed by anyone once they are published to the mempool. A way to prevent this would be to introduce a `paymentReceiver`.
- The payment logic adds additional code and could have been removed for an initial version. 

## Architecture

The contract has been designed to improve the gas usage when executing a transfer and to make it easy to interact with the contract. Because of this configuration changes (e.g. adding or removing allowance and delegates) are not optimized on gas usage.

Allowances are stored in a map called `allowances`. The key to this map is a combination of the Safe, the delegate and the token. Each allowance has the following fields:
- `uint96 amount`
  - Maximum amount that can be spent
- `uint96 spent`
  - Amount that has already been spent
- `uint16 resetTimeMin`
  - Time span in **minutes** after which the `spent` amount will automatically reset to `0`. If `resetTimeMin` is `0` the `spent` value will not automatically reset.
- `uint32 lastResetMin`
  - Point in time in **minutes** when the `spent` amount was last reset to `0`. This can be used to specify the point in time (e.g. time of a day) when the reset should happen, as each following reset will be based on last time.
- `uint16 nonce`
  - Increasing nonce that is used to protect transfer confirmations (e.g. signatures) against replay attacks.

Some limits have been applied to the different fields to make sure that the overall struct fits into a single **word** of storage:
- The maximum allowance is `2^96`. Assuming a token with 18 decimals that would allow an allowance from more than 70 billion, which seems sufficient.
- The maximum time span that can be used for the reset is `2**16` minutes. This corresponds to around 45 days, which is more than one month and should be sufficient for most use cases.
- The maximum reset time would be the unix epoch of `(2**32) * 60`. This is in the year 10136.
- The maximum numbers of transfers a delegate can do is `2**16` (aka `65536`) which should be sufficient, as it is easily possible to register a new delegate.

To make it easier to allow querying for allowances two more data structures have been added to the contract: `delegates` and `tokens`.

`delegates` stores all the delegates for a specific Safe in a double linked list. For this we also store an entry point to that double linked list in `delegatesStart`. Each delegate is identified by a `uint48` which is the first **6bytes** of the delegate address. This could theoretically cause collisions. Therfore the index points to a struct containing the `address` of the delgate, the `next` index and the `prev` index, so that it is possible to verify which address was used to get the index. In case of collisions we recommend to generate a new delegate.

`tokens` is a list that is appended when ever an allowance is set for a token for the first time. The tokens will never be removed from this list.

Using `delegates` and `tokens` it is possible to query all available allowances for a Safe. This is to avoid that there are any "hidden" allowances.

## Considerations

- If storage rent is introduced for contracts it might be possible (depending on the rent implementation) to perform a grieving attack, as anyone can register allowances.
- The information provided by `delegates` and `tokens` could be rebuilt using events and therefore these would not be necessary in the contract (this would make some consistency checks unnecessary and save gas).
- The bytes assigned to different parts of the `Allowance` struct could be optimized.

## Running tests

```bash
pnpm i
pnpm test
```

## Compiling contracts
```bash
pnpm i
pnpm build
```

## Deploying and verifying contracts

Specify all the necessary environment variables in `.env`, following the `.env.sample` file.

```bash
pnpm i
pnpm run deploy <network_name>
```

1. `network_name` is the name of the network you want to deploy to. It must be added to the hardhat config under `networks` beforehand.
2. If the hardhat plugin cannot figure out the etherscan API url for the network, you can add it manually to `tasks/deploy_verify.ts`.
Example:
```ts
await hre.run('etherscan-verify', {
  forceLicense: true,
  license: 'LGPL-3.0',
  apiUrl: "https://api.gnosiscan.io"
})
```


