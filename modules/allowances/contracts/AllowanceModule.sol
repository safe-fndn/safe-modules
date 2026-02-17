// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.8.0;

import "./Enum.sol";
import "./SignatureDecoder.sol";

interface ISafe {
    /// @dev Allows a Module to execute a Safe transaction without any further confirmations.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) external returns (bool success);

    /// @dev Allows a Module to execute a Safe transaction without any further confirmations with propagated return data.
    /// @param to Destination address of module transaction.
    /// @param value Ether value of module transaction.
    /// @param data Data payload of module transaction.
    /// @param operation Operation type of module transaction.
    function execTransactionFromModuleReturnData(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success, bytes memory returnData);
}

contract AllowanceModule is SignatureDecoder {
    /// @notice A descriptive name for the module.
    string public constant NAME = "Allowance Module";

    /// @notice The module version.
    string public constant VERSION = "1.0.0";

    /// @notice The precomputed EIP-712 domain separator type-hash.
    /// @dev This value is precomputed from:
    ///      keccak256("EIP712Domain(uint256 chainId,address verifyingContract))
    bytes32 public constant DOMAIN_SEPARATOR_TYPEHASH = 0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218;

    /// @notice The precomputed EIP-712 allowance transfer type-hash.
    /// @dev This value is precomputed from:
    ///      keccak256("AllowanceTransfer(address safe,address token,address to,uint96 amount,address paymentToken,uint96 payment,uint16 nonce)")
    bytes32 public constant ALLOWANCE_TRANSFER_TYPEHASH = 0x97c7ed08d51f4a077f71428543a8a2454799e5f6df78c03ef278be094511eda4;

    /// @notice A mapping of Safe -> Delegate -> Allowance
    mapping(address => mapping(address => mapping(address => Allowance))) public allowances;
    /// @notice A mapping of Safe -> Delegate -> Tokens
    mapping(address => mapping(address => address[])) public tokens;
    /// @notice A mapping of Safe -> Delegates doubly linked list entry points
    mapping(address => uint48) public delegatesStart;
    /// @notice A mapping of Safe -> Delegates doubly linked list
    mapping(address => mapping(uint48 => Delegate)) public delegates;

    /// @notice A delegate doubly linked list node.
    /// @dev We use a double linked list for the delegates. The id is the first 6 bytes.
    ///      To double check the address in case of collision, the address is part of the struct.
    struct Delegate {
        address delegate;
        uint48 prev;
        uint48 next;
    }

    /// @notice Allowance data.
    /// @dev The allowance info is optimized to fit into one word of storage.
    struct Allowance {
        uint96 amount;
        uint96 spent;
        uint16 resetTimeMin; // Maximum reset time span is 65k minutes
        uint32 lastResetMin;
        uint16 nonce;
    }

    /// @notice Event emitted when a delegate is registered for a Safe.
    /// @param safe The Safe that added the delegate.
    /// @param delegate The added delegate.
    event AddDelegate(address indexed safe, address delegate);

    /// @notice Event emitted when a delegate is unregistered for a Safe.
    /// @param safe The Safe that removed the delegate.
    /// @param delegate The removed delegate.
    event RemoveDelegate(address indexed safe, address delegate);

    /// @notice Event emitted when an allowance transfer is executed.
    /// @param safe The Safe with allowance that was used.
    /// @param delegate The delegate that authorized the spend.
    /// @param token The allowed token.
    /// @param to The recipient of the transfer.
    /// @param value The transferred amount.
    /// @param nonce The nonce for the delegate's allowance transfer.
    event ExecuteAllowanceTransfer(address indexed safe, address delegate, address token, address to, uint96 value, uint16 nonce);

    /// @notice Event emitted when a relayer is reimbursed for executing an allowance transfer.
    /// @param safe The Safe with allowance that was used.
    /// @param delegate The delegate that authorized the spend.
    /// @param paymentToken The token that was used for the payment.
    /// @param paymentReceiver The recipient of the payment.
    /// @param payment The paid amount.
    event PayAllowanceTransfer(address indexed safe, address delegate, address paymentToken, address paymentReceiver, uint96 payment);

    /// @notice Event emitted when an allowance is set.
    /// @param safe The Safe that set the allowance.
    /// @param delegate The delegate that can spend the allowance.
    /// @param token The allowed token.
    /// @param allowanceAmount The allowed amount.
    /// @param resetTime Time after which the allowance should reset in minutes.
    event SetAllowance(address indexed safe, address delegate, address token, uint96 allowanceAmount, uint16 resetTime);

    /// @notice Event emitted when an allowance is manually reset.
    /// @param safe The Safe that set the allowance.
    /// @param delegate The delegate for whom the allowance was reset.
    /// @param token The token for the reset allowance.
    event ResetAllowance(address indexed safe, address delegate, address token);

    /// @notice Event emitted when an allowance is revoked.
    /// @param safe The Safe that deleted the allowance.
    /// @param delegate The delegate for the deleted allowance.
    /// @param token The token for the deleted allowance.
    event DeleteAllowance(address indexed safe, address delegate, address token);

    /// @notice Set an allowance for a specified token. This can only be done via a Safe transaction.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token Token contract address, or `address(0)` for the native token.
    /// @param allowanceAmount allowance in smallest token unit.
    /// @param resetTimeMin Time after which the allowance should reset in minutes.
    /// @param resetBaseMin Time based on which the reset time should be increased in minutes.
    function setAllowance(address delegate, address token, uint96 allowanceAmount, uint16 resetTimeMin, uint32 resetBaseMin) public {
        require(delegate != address(0), "delegate != address(0)");
        require(
            delegates[msg.sender][uint48(delegate)].delegate == delegate,
            "delegates[msg.sender][uint48(delegate)].delegate == delegate"
        );
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        if (allowance.nonce == 0) {
            // New token
            // Nonce should never be 0 once allowance has been activated
            allowance.nonce = 1;
            tokens[msg.sender][delegate].push(token);
        }
        // Divide by 60 to get current time in minutes
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        if (resetBaseMin > 0) {
            require(resetBaseMin <= currentMin && resetTimeMin > 0, "resetBaseMin <= currentMin && resetTimeMin > 0");
            allowance.lastResetMin = currentMin - ((currentMin - resetBaseMin) % resetTimeMin);
        } else if (allowance.lastResetMin == 0) {
            allowance.lastResetMin = currentMin;
        }
        allowance.resetTimeMin = resetTimeMin;
        allowance.amount = allowanceAmount;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit SetAllowance(msg.sender, delegate, token, allowanceAmount, resetTimeMin);
    }

    /// @dev Reads an allowance from contract storage, ensuring that it is correctly reset in case
    ///      sufficient time has elapsed.
    /// @param safe The Safe to get the allowance for.
    /// @param delegate The delegate for the allowance.
    /// @param token The allowed token.
    /// @return allowance The allowance.
    function getAllowance(address safe, address delegate, address token) private view returns (Allowance memory allowance) {
        allowance = allowances[safe][delegate][token];
        // solium-disable-next-line security/no-block-members
        uint32 currentMin = uint32(block.timestamp / 60);
        // Check if we should reset the time. We do this on load to minimize storage read/ writes
        if (allowance.resetTimeMin > 0 && allowance.lastResetMin <= currentMin - allowance.resetTimeMin) {
            allowance.spent = 0;
            // Resets happen in regular intervals and `lastResetMin` should be aligned to that
            allowance.lastResetMin = currentMin - ((currentMin - allowance.lastResetMin) % allowance.resetTimeMin);
        }
        return allowance;
    }

    /// @dev Update an allowance.
    /// @param safe The Safe to update the allowance for.
    /// @param delegate The delegate for the allowance.
    /// @param token The allowed token.
    /// @param allowance The updated allowance data.
    function updateAllowance(address safe, address delegate, address token, Allowance memory allowance) private {
        allowances[safe][delegate][token] = allowance;
    }

    /// @notice Manually reset the allowance for a specific delegate and token.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token The allowed token.
    function resetAllowance(address delegate, address token) public {
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        allowance.spent = 0;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit ResetAllowance(msg.sender, delegate, token);
    }

    /// @notice Remove an allowance for a specific delegate and token. This will set all values
    ///         except the `nonce` to 0.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param token The allowed token.
    function deleteAllowance(address delegate, address token) public {
        Allowance memory allowance = getAllowance(msg.sender, delegate, token);
        allowance.amount = 0;
        allowance.spent = 0;
        allowance.resetTimeMin = 0;
        allowance.lastResetMin = 0;
        updateAllowance(msg.sender, delegate, token, allowance);
        emit DeleteAllowance(msg.sender, delegate, token);
    }

    /// @notice Use an allowance to perform a transfer.
    /// @param safe The Safe whose funds should be used.
    /// @param token Token contract address, or `address(0)` for the native token.
    /// @param to Address that should receive the tokens.
    /// @param amount Amount that should be transferred.
    /// @param paymentToken Token that should be used to pay for the execution of the transfer.
    /// @param payment Amount to should be paid for executing the transfer.
    /// @param delegate Delegate whose allowance should be updated.
    /// @param signature Signature generated by the delegate to authorize the transfer.
    function executeAllowanceTransfer(
        ISafe safe,
        address token,
        address payable to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        address delegate,
        bytes memory signature
    ) public {
        // Get current state
        Allowance memory allowance = getAllowance(address(safe), delegate, token);
        bytes memory transferHashData = generateTransferHashData(address(safe), token, to, amount, paymentToken, payment, allowance.nonce);

        // Check for nonces exhausted
        // Note that this implies that a delegate can _only_ execute 65534 different transfers for a
        // particular token allowance. We believe this is a reasonable limit. If more transfers are
        // needed than multiple delegate accounts must be used.
        require(allowance.nonce != type(uint16).max, "allowance.nonce != type(uint16).max (use different delegate)");
        // Update nonce
        allowance.nonce = allowance.nonce + 1;

        // Update spent amount
        uint96 newSpent = allowance.spent + amount;
        // Check new spent amount and overflow
        require(newSpent > allowance.spent && newSpent <= allowance.amount, "newSpent > allowance.spent && newSpent <= allowance.amount");
        allowance.spent = newSpent;
        if (payment > 0) {
            // Use updated allowance if token and paymentToken are the same
            Allowance memory paymentAllowance = paymentToken == token ? allowance : getAllowance(address(safe), delegate, paymentToken);
            newSpent = paymentAllowance.spent + payment;
            // Check new spent amount and overflow
            require(
                newSpent > paymentAllowance.spent && newSpent <= paymentAllowance.amount,
                "newSpent > paymentAllowance.spent && newSpent <= paymentAllowance.amount"
            );
            paymentAllowance.spent = newSpent;
            // Update payment allowance if different from allowance
            if (paymentToken != token) updateAllowance(address(safe), delegate, paymentToken, paymentAllowance);
        }
        updateAllowance(address(safe), delegate, token, allowance);

        // Perform external interactions
        // Check signature
        checkSignature(delegate, signature, transferHashData, safe);

        if (payment > 0) {
            // Transfer payment
            // solium-disable-next-line security/no-tx-origin
            transfer(safe, paymentToken, tx.origin, payment);
            // solium-disable-next-line security/no-tx-origin
            emit PayAllowanceTransfer(address(safe), delegate, paymentToken, tx.origin, payment);
        }
        // Transfer token
        transfer(safe, token, to, amount);
        emit ExecuteAllowanceTransfer(address(safe), delegate, token, to, amount, allowance.nonce - 1);
    }

    /// @notice Returns the chain id used by this contract.
    function getChainId() public pure returns (uint256) {
        uint256 id;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            id := chainid()
        }
        return id;
    }

    /// @dev Generates the pre-image for the transfer hash that is signed by the delegate to
    ///      authorize an allowance transfer.
    /// @param safe The Safe whose funds should be used.
    /// @param token The allowed token.
    /// @param to Address that should receive the tokens.
    /// @param amount Amount that should be transferred.
    /// @param paymentToken Token that should be used to pay for the execution of the transfer.
    /// @param payment Amount to should be paid for executing the transfer.
    /// @param nonce The delegate's transfer nonce.
    /// @return The transfer hash pre-image.
    function generateTransferHashData(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) private view returns (bytes memory) {
        uint256 chainId = getChainId();
        bytes32 domainSeparator = keccak256(abi.encode(DOMAIN_SEPARATOR_TYPEHASH, chainId, this));
        bytes32 transferHash = keccak256(abi.encode(ALLOWANCE_TRANSFER_TYPEHASH, safe, token, to, amount, paymentToken, payment, nonce));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, transferHash);
    }

    /// @notice Generates the transfer hash that should be signed to authorize a transfer
    /// @param safe The Safe whose funds should be used.
    /// @param token The allowed token.
    /// @param to Address that should receive the tokens.
    /// @param amount Amount that should be transferred.
    /// @param paymentToken Token that should be used to pay for the execution of the transfer.
    /// @param payment Amount to should be paid for executing the transfer.
    /// @param nonce The delegate's transfer nonce.
    /// @return The transfer hash.
    function generateTransferHash(
        address safe,
        address token,
        address to,
        uint96 amount,
        address paymentToken,
        uint96 payment,
        uint16 nonce
    ) public view returns (bytes32) {
        return keccak256(generateTransferHashData(safe, token, to, amount, paymentToken, payment, nonce));
    }

    /// @dev Checks the signature for the specified transfer hash matches the expected delegate.
    /// @param expectedDelegate The expected delegate address that signature should recover to.
    /// @param signature The encoded signature.
    /// @param transferHashData The transfer hash pre-image.
    /// @param safe The Safe providing the allowance for the transfer.
    function checkSignature(address expectedDelegate, bytes memory signature, bytes memory transferHashData, ISafe safe) private view {
        address signer = recoverSignature(signature, transferHashData);
        require(
            expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer,
            "expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer"
        );
    }

    /// @dev ECDSA recovery of an encoded signature and a given transfer hash pre-image. This
    ///      module uses a similar format to the Safe contract, except that it only supports exactly
    ///      one signature and no contract signatures. In addition, an empty signature can also be
    ///      provided in order to authenticate with the caller (i.e. `msg.sender`).
    /// @param signature The encoded signature.
    /// @param transferHashData The transfer hash pre-image.
    /// @return owner The recovered signer.
    function recoverSignature(bytes memory signature, bytes memory transferHashData) private view returns (address owner) {
        // If there is no signature data msg.sender should be used
        if (signature.length == 0) return msg.sender;
        // Check that the provided signature data is as long as 1 encoded ECDSA signature
        require(signature.length == 65, "signatures.length == 65");
        uint8 v;
        bytes32 r;
        bytes32 s;
        (v, r, s) = signatureSplit(signature, 0);
        // If v is 0 then it is a contract signature
        if (v == 0) {
            revert("Contract signatures are not supported by this module");
        } else if (v == 1) {
            // If v is 1 we also use msg.sender, this is so that we are compatible to the Safe signature scheme
            owner = msg.sender;
        } else if (v > 30) {
            // To support eth_sign and similar we adjust v and hash the transferHashData with the Ethereum message prefix before applying ecrecover
            owner = ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", keccak256(transferHashData))), v - 4, r, s);
        } else {
            // Use ecrecover with the messageHash for EOA signatures
            owner = ecrecover(keccak256(transferHashData), v, r, s);
        }
        // 0 for the recovered owner indicates that an error happened.
        require(owner != address(0), "owner != address(0)");
    }

    /// @dev Internal function to execute an authorized allowance token transfer.
    /// @param token Token contract address, or `address(0)` for the native token.
    /// @param to Address that should receive the tokens.
    /// @param amount Amount that should be transferred.
    function transfer(ISafe safe, address token, address payable to, uint96 amount) private {
        if (token == address(0)) {
            // solium-disable-next-line security/no-send
            require(safe.execTransactionFromModule(to, amount, "", Enum.Operation.Call), "Could not execute ether transfer");
        } else {
            bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", to, amount);
            (bool success, bytes memory returnData) = safe.execTransactionFromModuleReturnData(token, 0, data, Enum.Operation.Call);
            if (success && returnData.length > 0) {
                success = abi.decode(returnData, (bool));
            }
            require(success, "Could not execute token transfer");
        }
    }

    /// @notice Get the list of tokens that a delegate was given allowances to.
    /// @dev This list includes past allowances that have been either revoked or completely spent.
    /// @param safe The Safe that has given allowances.
    /// @param delegate The delegate that was allowed to spend tokens.
    /// @return The list of tokens that a delegate has received allowances for.
    function getTokens(address safe, address delegate) public view returns (address[] memory) {
        return tokens[safe][delegate];
    }

    /// @notice Gets an allowance.
    /// @param safe The Safe that gave the allowance.
    /// @param delegate The delegate that was allowed to spend.
    /// @param token The allowance token.
    /// @return The allowance data parameters as `[amount, spent, resetTimeMin, lastResetMin, nonce]`.
    function getTokenAllowance(address safe, address delegate, address token) public view returns (uint256[5] memory) {
        Allowance memory allowance = getAllowance(safe, delegate, token);
        return [
            uint256(allowance.amount),
            uint256(allowance.spent),
            uint256(allowance.resetTimeMin),
            uint256(allowance.lastResetMin),
            uint256(allowance.nonce)
        ];
    }

    /// @notice Add a delegate.
    /// @param delegate Delegate that should be added.
    function addDelegate(address delegate) public {
        uint48 index = uint48(delegate);
        require(index != uint(0), "index != uint(0)");
        address currentDelegate = delegates[msg.sender][index].delegate;
        if (currentDelegate != address(0)) {
            // We have a collision for the indices of delegates
            require(currentDelegate == delegate, "currentDelegate == delegate");
            // Delegate already exists, nothing to do
            return;
        }
        uint48 startIndex = delegatesStart[msg.sender];
        delegates[msg.sender][index] = Delegate(delegate, 0, startIndex);
        delegates[msg.sender][startIndex].prev = index;
        delegatesStart[msg.sender] = index;
        emit AddDelegate(msg.sender, delegate);
    }

    /// @notice Remove a delegate.
    /// @param delegate Delegate that should be removed.
    /// @param removeAllowances Whether or not allowances should also be removed. This should be
    ///                         set to `true` unless this causes an out of gas, in this case the
    ///                         allowances should be deleted one-by-one with `deleteAllowance`.
    function removeDelegate(address delegate, bool removeAllowances) public {
        Delegate memory current = delegates[msg.sender][uint48(delegate)];
        // Delegate doesn't exists, nothing to do
        if (current.delegate == address(0)) return;
        // Make sure that the we are deleting the right delegate
        require(current.delegate == delegate, "current.delegate == delegate");
        if (removeAllowances) {
            address[] storage delegateTokens = tokens[msg.sender][delegate];
            for (uint256 i = 0; i < delegateTokens.length; i++) {
                address token = delegateTokens[i];
                // Set all allowance params except the nonce to 0
                Allowance memory allowance = getAllowance(msg.sender, delegate, token);
                allowance.amount = 0;
                allowance.spent = 0;
                allowance.resetTimeMin = 0;
                allowance.lastResetMin = 0;
                updateAllowance(msg.sender, delegate, token, allowance);
                emit DeleteAllowance(msg.sender, delegate, token);
            }
        }
        if (current.prev == 0) {
            delegatesStart[msg.sender] = current.next;
        } else {
            delegates[msg.sender][current.prev].next = current.next;
        }
        if (current.next != 0) {
            delegates[msg.sender][current.next].prev = current.prev;
        }
        delete delegates[msg.sender][uint48(delegate)];
        emit RemoveDelegate(msg.sender, delegate);
    }

    /// @notice Gets the list of delegates with allowances for a given Safe.
    /// @dev This function provides a paginated interface.
    /// @param safe The Safe to retrieve delegates for.
    /// @param start The starting delegate key to retrieve delegates.
    /// @param pageSize The maximum number of delegates to retrieve.
    /// @return results The delegate addresses.
    /// @return next The delegate key to start retrieving the next page.
    function getDelegates(address safe, uint48 start, uint8 pageSize) public view returns (address[] memory results, uint48 next) {
        results = new address[](pageSize);
        uint8 i = 0;
        uint48 initialIndex = (start != 0) ? start : delegatesStart[safe];
        Delegate memory current = delegates[safe][initialIndex];
        while (current.delegate != address(0) && i < pageSize) {
            results[i] = current.delegate;
            i++;
            current = delegates[safe][current.next];
        }
        next = uint48(current.delegate);
        // Set the length of the array the number that has been used.
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(results, i)
        }
    }
}
