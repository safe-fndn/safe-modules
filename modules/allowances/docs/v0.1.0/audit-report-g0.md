# Gnosis Safe Allowance Module / October 2020

### Files in scope

All solidity files in:

<https://github.com/gnosis/safe-modules/tree/c75f190e5d55e88e98c20f802e3e9eadedfb52f6>

### Current status

All found issues have been fixed.

### Issues

### 1. delegatesStart not updated in removeDelegate 

#### Severity: medium

`removeDelegate` doesn't update delegatesStart which will break the delegate linked list.

#### status - fixed

The issue is no longer present in

<https://github.com/gnosis/safe-modules/tree/b531c8db9ded1fa72c8459078ebe4e88a2501bae>

### 2. Delegates are not really removed

#### Severity: medium

`removeDelegate` doesn't functionally remove the delegates, they can still have allowances and they can't be added back in with `addDelegate`. RemoveDelegate only affects the output of `getDelegates`.

#### status - fixed

The issue is no longer present in

<https://github.com/gnosis/safe-modules/tree/b531c8db9ded1fa72c8459078ebe4e88a2501bae>

### 3. Return value of ecrecover not checked for 0

#### Severity: medium

`ecrecover` returns `0` on failure, which will lead to this check passing, this isn't a security vulnerability if there are no allowances for the `0` address, but is still unexpected.

#### status - fixed

The issue is no longer present in

<https://github.com/gnosis/safe-modules/tree/b531c8db9ded1fa72c8459078ebe4e88a2501bae>