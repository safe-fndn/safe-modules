// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.0 <0.9.0;

/// @dev A token that with a _technically_ standard-compliant ERC-20 `transfer` implementation that
///      returns `false` instead of reverting on failure.
contract WeirdToken {
    function transfer(address, uint256) external pure returns (bool success) {
        return false;
    }
}
