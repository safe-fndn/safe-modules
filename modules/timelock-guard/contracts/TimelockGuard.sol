// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.0 <0.9.0;

import {BaseTransactionGuard, ITransactionGuard} from "@safe-global/safe-smart-account/contracts/base/GuardManager.sol";
import {ISafe} from "@safe-global/safe-smart-account/contracts/interfaces/ISafe.sol";
import {Enum} from "@safe-global/safe-smart-account/contracts/libraries/Enum.sol";

/**
 * @title TimelockGuard
 * @notice A Safe transaction guard that enforces a configurable delay between when a multisig
 *         transaction is approved and when it can be executed.
 * @dev Implements {ITransactionGuard} from Safe Smart Account v1.5.0. A single deployment of
 *      this contract serves any number of Safes; all state is keyed by the Safe address.
 *
 *      Lifecycle:
 *        1. Owners call {scheduleTransaction} (off-chain signing + one on-chain call).
 *           The guard verifies the threshold of signatures on-chain.
 *        2. After the configured delay elapses, the standard {ISafe-execTransaction} flow
 *           proceeds normally. {checkTransaction} enforces that the tx was scheduled and is ready.
 *        3. {checkAfterExecution} clears the schedule entry on success.
 *        4. At any point before execution, {cancel} can abort the scheduled tx.
 *
 *      Configuration (setUp / updateDelay / setCanceller) requires `msg.sender == safe`, meaning
 *      these calls must themselves go through {ISafe-execTransaction} — and are therefore
 *      timelocked once the guard is active. This prevents instant removal of the timelock.
 *
 *      Bootstrapping: call {setUp} before installing the guard via {GuardManager-setGuard}.
 *      After installation, removing or reconfiguring the guard is itself subject to the delay.
 *
 * @author Hayden Wolfe
 * @custom:upstream-issue https://github.com/safe-fndn/safe-smart-account/issues/1065
 */
contract TimelockGuard is BaseTransactionGuard {
    // ─── Immutables ──────────────────────────────────────────────────────────

    /// @notice Floor delay (seconds) any Safe may configure. Set at deployment and immutable.
    uint256 public immutable MIN_DELAY;

    /// @notice Ceiling delay (seconds) any Safe may configure. Set at deployment and immutable.
    uint256 public immutable MAX_DELAY;

    // ─── Storage ─────────────────────────────────────────────────────────────

    /// @dev Per-Safe configured delay in seconds. Zero means this Safe has not called {setUp}.
    mapping(address safe => uint256 delay) private _delays;

    /// @dev Per-Safe schedule book. Value is the unix timestamp at which the tx becomes executable.
    ///      Zero means unscheduled.
    mapping(address safe => mapping(bytes32 txHash => uint256 readyAt)) private _schedules;

    /// @dev Per-Safe canceller allowlist. Addresses that may call {cancel} for that Safe.
    mapping(address safe => mapping(address canceller => bool enabled)) private _cancellers;

    // ─── Events ──────────────────────────────────────────────────────────────

    event TimelockSetUp(address indexed safe, uint256 delay);
    event DelayUpdated(address indexed safe, uint256 oldDelay, uint256 newDelay);
    event CancellerUpdated(address indexed safe, address indexed account, bool enabled);
    event TransactionScheduled(
        address indexed safe,
        bytes32 indexed txHash,
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation,
        uint256 nonce,
        uint256 readyAt
    );
    event TransactionExecuted(address indexed safe, bytes32 indexed txHash);
    event TransactionCancelled(address indexed safe, bytes32 indexed txHash, address indexed canceller);

    // ─── Errors ──────────────────────────────────────────────────────────────

    error NotSafe();
    error NotAuthorizedCanceller();
    error DelayBelowMinimum(uint256 provided, uint256 min);
    error DelayAboveMaximum(uint256 provided, uint256 max);
    error TimelockNotConfigured(address safe);
    error AlreadyScheduled(bytes32 txHash);
    error NotScheduled(bytes32 txHash);
    error DelayNotElapsed(uint256 readyAt, uint256 nowTs);
    error NonceInThePast(uint256 provided, uint256 current);

    // ─── Constructor ─────────────────────────────────────────────────────────

    /**
     * @param minDelay Minimum delay in seconds that any Safe may configure. Must be > 0.
     * @param maxDelay Maximum delay in seconds that any Safe may configure. Must be >= minDelay.
     */
    constructor(uint256 minDelay, uint256 maxDelay) {
        // TODO: require(minDelay > 0, "TimelockGuard: minDelay must be > 0")
        // TODO: require(maxDelay >= minDelay, "TimelockGuard: maxDelay must be >= minDelay")
        MIN_DELAY = minDelay;
        MAX_DELAY = maxDelay;
    }

    // solhint-disable-next-line payable-fallback
    fallback() external {
        // We do not revert on fallback to avoid locking the Safe if the guard interface
        // ever gains new methods after this guard is installed.
    }

    // ─── Configuration ───────────────────────────────────────────────────────

    /**
     * @notice Initializes the timelock delay for the calling Safe.
     * @dev Must be called by the Safe via {ISafe-execTransaction} *before* {GuardManager-setGuard}
     *      installs this guard — otherwise this call will itself require a scheduled transaction.
     *      Reverts if already configured; call {updateDelay} to change an existing delay.
     * @param delay Initial delay in seconds. Must be within [MIN_DELAY, MAX_DELAY].
     */
    function setUp(uint256 delay) external {
        // TODO: require(_delays[msg.sender] == 0, "TimelockGuard: already configured; use updateDelay")
        // TODO: _validateDelay(delay)
        // TODO: _delays[msg.sender] = delay
        // TODO: emit TimelockSetUp(msg.sender, delay)
    }

    /**
     * @notice Updates the timelock delay for the calling Safe.
     * @dev Must be called by the Safe itself. Already-pending transactions retain their original
     *      readyAt timestamp; only new schedules use the updated delay.
     * @param newDelay New delay in seconds. Must be within [MIN_DELAY, MAX_DELAY].
     */
    function updateDelay(uint256 newDelay) external {
        // TODO: require(_delays[msg.sender] != 0, TimelockNotConfigured(msg.sender))
        // TODO: _validateDelay(newDelay)
        // TODO: uint256 old = _delays[msg.sender]
        // TODO: _delays[msg.sender] = newDelay
        // TODO: emit DelayUpdated(msg.sender, old, newDelay)
    }

    /**
     * @notice Grants or revokes cancel rights for an address on the calling Safe.
     * @dev Must be called by the Safe itself.
     * @param account Address to grant or revoke.
     * @param enabled True to grant, false to revoke.
     */
    function setCanceller(address account, bool enabled) external {
        // TODO: require(_delays[msg.sender] != 0, TimelockNotConfigured(msg.sender))
        // TODO: _cancellers[msg.sender][account] = enabled
        // TODO: emit CancellerUpdated(msg.sender, account, enabled)
    }

    // ─── Lifecycle ───────────────────────────────────────────────────────────

    /**
     * @notice Schedules a Safe transaction for delayed execution.
     * @dev The parameters mirror {ISafe-execTransaction} exactly, with `nonce` exposed explicitly.
     *      Anyone may call this function — authorization comes from the signatures, not the caller.
     *      Signatures are verified on-chain by calling {ISafe-checkSignatures} on the target Safe.
     *
     *      After the configured delay elapses, calling {ISafe-execTransaction} with identical
     *      parameters will succeed: {checkTransaction} will find the schedule and allow execution.
     *
     * @param safe         The Safe to schedule the transaction for.
     * @param to           Destination address.
     * @param value        Native token value (wei).
     * @param data         Call data.
     * @param operation    {Enum.Operation} — CALL or DELEGATECALL.
     * @param safeTxGas    Gas allocated for the inner call.
     * @param baseGas      Base gas (signature check, payment overhead).
     * @param gasPrice     Gas price for the refund calculation.
     * @param gasToken     Token used for the refund (address(0) for native).
     * @param refundReceiver Recipient of the gas refund.
     * @param nonce        Safe nonce. Must be >= the Safe's current nonce.
     * @param signatures   Packed owner signatures over the Safe transaction hash.
     * @return txHash      The Safe transaction hash that was scheduled.
     * @return readyAt     Unix timestamp at which the transaction becomes executable.
     */
    function scheduleTransaction(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        uint256 nonce,
        bytes calldata signatures
    ) external returns (bytes32 txHash, uint256 readyAt) {
        // TODO: uint256 delay = _delays[safe]
        // TODO: if (delay == 0) revert TimelockNotConfigured(safe)
        // TODO: uint256 currentNonce = ISafe(safe).nonce()
        // TODO: if (nonce < currentNonce) revert NonceInThePast(nonce, currentNonce)
        // TODO: txHash = ISafe(safe).getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
        // TODO: if (_schedules[safe][txHash] != 0) revert AlreadyScheduled(txHash)
        // TODO: ISafe(safe).checkSignatures(address(this), txHash, signatures)
        // TODO: readyAt = block.timestamp + delay
        // TODO: _schedules[safe][txHash] = readyAt
        // TODO: emit TransactionScheduled(safe, txHash, to, value, data, operation, nonce, readyAt)
    }

    /**
     * @notice Cancels a previously scheduled transaction.
     * @dev Caller must be the Safe itself or an address listed in the Safe's canceller allowlist.
     * @param safe   The Safe that owns the schedule.
     * @param txHash The Safe transaction hash to cancel.
     */
    function cancel(address safe, bytes32 txHash) external {
        // TODO: if (msg.sender != safe && !_cancellers[safe][msg.sender]) revert NotAuthorizedCanceller()
        // TODO: if (_schedules[safe][txHash] == 0) revert NotScheduled(txHash)
        // TODO: delete _schedules[safe][txHash]
        // TODO: emit TransactionCancelled(safe, txHash, msg.sender)
    }

    // ─── Guard hooks ─────────────────────────────────────────────────────────

    /**
     * @inheritdoc ITransactionGuard
     * @dev Called by Safe.execTransaction after signature verification and nonce increment.
     *      The Safe's nonce is already post-incremented at this point, so the nonce used to
     *      compute the current txHash is `ISafe(msg.sender).nonce() - 1`.
     *      Reverts unless the transaction was previously scheduled and the delay has elapsed.
     */
    function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        // solhint-disable-next-line no-unused-vars
        address payable refundReceiver,
        bytes memory, /* signatures */
        address /* msgSender */
    ) external view override {
        // TODO: uint256 nonce = ISafe(msg.sender).nonce() - 1
        // TODO: bytes32 txHash = ISafe(msg.sender).getTransactionHash(to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, nonce)
        // TODO: uint256 readyAt = _schedules[msg.sender][txHash]
        // TODO: if (readyAt == 0) revert NotScheduled(txHash)
        // TODO: if (block.timestamp < readyAt) revert DelayNotElapsed(readyAt, block.timestamp)
    }

    /**
     * @inheritdoc ITransactionGuard
     * @dev Clears the schedule entry after a successful execution to prevent replay.
     *      If execution failed, the entry is left intact: signers may resubmit (note that Safe
     *      increments its nonce even on failure, so a new scheduling call will be required).
     */
    function checkAfterExecution(bytes32 txHash, bool success) external override {
        // TODO: if (success) {
        //          delete _schedules[msg.sender][txHash]
        //          emit TransactionExecuted(msg.sender, txHash)
        //       }
    }

    // ─── Views ───────────────────────────────────────────────────────────────

    /// @notice Returns the configured delay for a Safe (0 if not yet set up).
    function getDelay(address safe) external view returns (uint256) {
        return _delays[safe];
    }

    /// @notice Returns the unix timestamp at which a scheduled tx becomes executable (0 if not scheduled).
    function getReadyAt(address safe, bytes32 txHash) external view returns (uint256) {
        return _schedules[safe][txHash];
    }

    /// @notice Returns whether an address is an authorized canceller for a Safe.
    function isCanceller(address safe, address account) external view returns (bool) {
        return _cancellers[safe][account];
    }

    // ─── Internal ────────────────────────────────────────────────────────────

    // TODO: function _validateDelay(uint256 delay) internal view {
    //          if (delay < MIN_DELAY) revert DelayBelowMinimum(delay, MIN_DELAY)
    //          if (delay > MAX_DELAY) revert DelayAboveMaximum(delay, MAX_DELAY)
    //       }
}
