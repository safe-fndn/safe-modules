import { expect } from 'chai'
import { ZeroAddress, toBeHex, AbiCoder, keccak256 } from 'ethers'
import hre, { deployments } from 'hardhat'

import execSafeTransaction from '../test/test-helpers/execSafeTransaction'
import setup from '../test/test-helpers/setup'

describe('AllowanceModule nonceOverflow', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    return setup(deployments)
  })

  it('Should revert on nonce overflow', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const { chainId } = await hre.ethers.provider.getNetwork()
    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    // 1. Setup Delegate and Allowance
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 1000, 0, 0), owner)

    // 2. Manipulate storage to simulate 65534 previous transfers
    const ALLOWANCES_SLOT = 0
    const coder = AbiCoder.defaultAbiCoder()

    // 2.1 Calculate mapping slot
    const slotSafe = keccak256(coder.encode(['address', 'uint256'], [safeAddress, ALLOWANCES_SLOT]))
    const slotDelegate = keccak256(coder.encode(['address', 'bytes32'], [alice.address, slotSafe]))
    const slotFinal = keccak256(coder.encode(['address', 'bytes32'], [tokenAddress, slotDelegate]))

    // 2.2 Read current storage
    const currentStorage = await hre.ethers.provider.getStorage(allowanceAddress, slotFinal)

    // 2.3 Set the nonce to 65535 (0xFFFF), as if there were 65534 previous transfers
    // Note that the slot has the following bit-layout (note **reverse** order from struct fields):
    // nonce(16) | lastReset(32) | resetTime(16) | spent(96) | amount(96)
    // This means that we need to set the most significant 2 bytes to `0xffff`
    const newStorage = toBeHex(BigInt(currentStorage) | (0xffffn << 240n))
    await hre.network.provider.send('hardhat_setStorageAt', [allowanceAddress, slotFinal, newStorage])

    // 2.4 Verify nonce is 65535.
    const [, , , , modifiedNonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(modifiedNonce).to.equal(0xffff)

    // 3. Verify that doing another transfer will revert on a nonce overflow.
    const transferAmount = 10
    const signature = await alice.signTypedData(
      {
        chainId,
        verifyingContract: allowanceAddress,
      },
      {
        AllowanceTransfer: [
          { type: 'address', name: 'safe' },
          { type: 'address', name: 'token' },
          { type: 'address', name: 'to' },
          { type: 'uint96', name: 'amount' },
          { type: 'address', name: 'paymentToken' },
          { type: 'uint96', name: 'payment' },
          { type: 'uint16', name: 'nonce' },
        ],
      },
      {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: transferAmount,
        paymentToken: ZeroAddress,
        payment: 0,
        nonce: 0xffff,
      },
    )
    await expect(
      allowanceModule.executeAllowanceTransfer(
        safeAddress,
        tokenAddress,
        bob.address,
        transferAmount,
        ZeroAddress,
        0,
        alice.address,
        signature,
      ),
    ).to.be.revertedWith('allowance.nonce != type(uint16).max (use different delegate)')
  })
})
