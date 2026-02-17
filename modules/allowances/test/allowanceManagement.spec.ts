import { expect } from 'chai'
import execAllowanceTransfer from './test-helpers/execAllowanceTransfer'
import execSafeTransaction from './test-helpers/execSafeTransaction'
import setup from './test-helpers/setup'
import { deployments } from 'hardhat'
import hre from 'hardhat'
import { ZeroAddress } from 'ethers'

describe('AllowanceModule allowanceManagement', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    return setup(deployments)
  })

  it('Revert when delegate addresses collide', async () => {
    const { safe, allowanceModule, owner, alice, bob } = await setupTests()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    const collidingDelegateAddress = hre.ethers.getAddress(`0x${bob.address.slice(2, -12)}${alice.address.slice(-12)}`.toLowerCase())

    await expect(
      execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(collidingDelegateAddress), owner),
    ).to.be.revertedWith('GS013')

    await allowanceModule.connect(owner).addDelegate(alice.address)
    await expect(allowanceModule.connect(owner).addDelegate(collidingDelegateAddress)).to.be.revertedWith('currentDelegate == delegate')
  })

  it('Cannot set allowance for address(0)', async () => {
    const { token, allowanceModule } = await setupTests()

    const tokenAddress = await token.getAddress()

    await expect(allowanceModule.setAllowance(ZeroAddress, tokenAddress, 0, 0, 0)).to.be.revertedWith('delegate != address(0)')
  })

  it('Delegate address cannot be address(0)', async () => {
    const { allowanceModule } = await setupTests()

    await expect(allowanceModule.addDelegate(ZeroAddress)).to.be.revertedWith('index != uint(0)')
  })

  it('Do not emit event if delegate already added', async () => {
    const { safe, allowanceModule, owner, alice } = await setupTests()

    // add alice as delegate
    await expect(await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner))
      .to.emit(allowanceModule, 'AddDelegate')
      .withArgs(safe.target, alice.address)

    // add alice as delegate again
    await expect(await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)).to.not.emit(
      allowanceModule,
      'AddDelegate',
    )
  })

  it("Do not emit event if delegate doesn't exist when removing", async () => {
    const { safe, allowanceModule, owner, alice } = await setupTests()

    await expect(
      await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, false), owner),
    ).to.not.emit(allowanceModule, 'AddDelegate')
  })

  it('Add delegates and removes first delegate', async () => {
    const { safe, allowanceModule, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add bob as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(bob.address), owner)

    let delegates = await allowanceModule.getDelegates(safeAddress, 0, 10)

    expect(delegates.results).to.deep.equal([bob.address, alice.address])
    expect(delegates.next).to.equal(0)

    // remove bob
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(bob.address, true), owner)
    delegates = await allowanceModule.getDelegates(safeAddress, 0, 10)

    expect(delegates.results).to.deep.equal([alice.address])
    expect(delegates.next).to.equal(0)
  })

  it('Add delegates and removes second delegate', async () => {
    const { safe, allowanceModule, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled.staticCall(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add bob as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(bob.address), owner)

    let delegates = await allowanceModule.getDelegates(safeAddress, 0, 10)

    expect(delegates.results).to.deep.equal([bob.address, alice.address])
    expect(delegates.next).to.equal(0)

    // remove alice
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)
    delegates = await allowanceModule.getDelegates(safeAddress, 0, 10)

    expect(delegates.results).to.deep.equal([bob.address])
    expect(delegates.next).to.equal(0)
  })

  it('Add and remove delegate and then try to execute', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()
    const tokenAddress = await token.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 1000, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 100,
      spender: alice,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(900)
    expect(await token.balanceOf(bob.address)).to.equal(100)

    // remove alice
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)

    // does not work after removing delegate
    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 100,
        spender: alice,
      }),
    ).to.be.revertedWith('newSpent > allowance.spent && newSpent <= allowance.amount')
  })

  it('Get delegates from non-zero start index', async () => {
    const { safe, allowanceModule, owner, alice, bob, charlie } = await setupTests()

    const safeAddress = await safe.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add bob as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(bob.address), owner)

    // add charlie as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(charlie.address), owner)

    const [delegates, next] = await allowanceModule.getDelegates(safeAddress, `0x${bob.address.slice(-12)}`, 10)

    expect(delegates).to.deep.equal([bob.address, alice.address])
    expect(next).to.equal(0)
  })

  it('Explicitly save allowances even after removing delegate', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()
    const tokenAddress = await token.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 1000, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 50,
      spender: alice,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(950)
    expect(await token.balanceOf(bob.address)).to.equal(50)

    // remove alice
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, false), owner)

    // Add alice as delegate again
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    const [amount, spent, resetTimeMin, lastResetMin, nonce] = await allowanceModule.getTokenAllowance(
      safeAddress,
      alice.address,
      tokenAddress,
    )

    expect(amount).to.equal(1000)
    expect(spent).to.equal(50)
    expect(resetTimeMin).to.equal(0)
    expect(lastResetMin).to.not.equal(0)
    expect(nonce).to.equal(2)

    // Work after adding delegate again as the allowances are not removed
    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 50,
      spender: alice,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(900)
    expect(await token.balanceOf(bob.address)).to.equal(100)
  })

  it('Does not remove delegates with key collision', async () => {
    const { safe, allowanceModule, owner, alice } = await setupTests()

    const safeAddress = await safe.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    const delegates = await allowanceModule.getDelegates(safeAddress, 0, 10)

    expect(delegates.results).to.deep.equal([alice.address])
    expect(delegates.next).to.equal(0)

    // remove alice-like fails
    const aliceLike = hre.ethers.getAddress(hre.ethers.zeroPadValue(hre.ethers.dataSlice(alice.address, 14), 20))
    await expect(
      execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(aliceLike, true), owner),
    ).to.be.revertedWith('GS013')
  })

  it('Cannot set allowance without delegate configured', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()
    const tokenAddress = await token.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // does not work without a delegate previously set
    await expect(
      execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner),
    ).to.be.revertedWith('GS013')

    // does not work without an allowance
    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 10,
        spender: alice,
      }),
    ).to.be.revertedWith('newSpent > allowance.spent && newSpent <= allowance.amount')

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))
  })

  it('Overwrite previous allowance', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 500, 1, 1), owner)

    const [amount, spent, resetTimeMin, lastResetMin, nonce] = await allowanceModule.getTokenAllowance(
      safeAddress,
      alice.address,
      tokenAddress,
    )
    expect(amount).to.equal(500)
    expect(spent).to.equal(0)
    expect(resetTimeMin).to.equal(1)
    expect(lastResetMin).to.not.equal(0)
    expect(nonce).to.equal(1)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 100,
      spender: alice,
    })

    expect(900).to.equal(await token.balanceOf(safeAddress))
    expect(100).to.equal(await token.balanceOf(bob.address))

    // Overwrite allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    const [newAmount, newSpent, newResetTimeMin, newLastResetMin, newNonce] = await allowanceModule.getTokenAllowance(
      safeAddress,
      alice.address,
      tokenAddress,
    )

    expect(newAmount).to.equal(100)
    expect(newSpent).to.equal(100)
    expect(newResetTimeMin).to.equal(0)
    expect(newLastResetMin).to.not.equal(0)
    expect(newNonce).to.equal(2)
  })

  it('Reset allowance', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 500, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 500,
      spender: alice,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(500)
    expect(await token.balanceOf(bob.address)).to.equal(500)

    // reset alice's allowance
    await expect(
      await execSafeTransaction(safe, await allowanceModule.resetAllowance.populateTransaction(alice.address, tokenAddress), owner),
    )
      .to.emit(allowanceModule, 'ResetAllowance')
      .withArgs(safeAddress, alice.address, tokenAddress)

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 500,
      spender: alice,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(0)
    expect(await token.balanceOf(bob.address)).to.equal(1000)
  })

  it('Delete allowance', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 500, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    // delete alice's allowance
    await expect(
      await execSafeTransaction(safe, await allowanceModule.deleteAllowance.populateTransaction(alice.address, tokenAddress), owner),
    )
      .to.emit(allowanceModule, 'DeleteAllowance')
      .withArgs(safeAddress, alice.address, tokenAddress)

    // does not work without an allowance
    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 500,
        spender: alice,
      }),
    ).to.be.revertedWith('newSpent > allowance.spent && newSpent <= allowance.amount')

    expect(await token.balanceOf(safeAddress)).to.equal(1000)
    expect(await token.balanceOf(bob.address)).to.equal(0)
  })

  it('Use allowance with payment in same token', async () => {
    const { safe, allowanceModule, token, owner, alice, bob, charlie } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))
    expect(0).to.equal(await token.balanceOf(charlie.address))

    await execAllowanceTransfer(allowanceModule.connect(charlie), {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 99,
      spender: alice,
      paymentToken: tokenAddress,
      payment: 1,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(900)
    expect(await token.balanceOf(bob.address)).to.equal(99)
    expect(await token.balanceOf(charlie.address)).to.equal(1)
  })

  it('Use allowance with payment in different token', async () => {
    const { safe, allowanceModule, token, owner, alice, bob, charlie } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const paymentToken = await (await hre.ethers.getContractFactory('TestToken')).deploy()
    await paymentToken.mint(safeAddress, 1000)
    const paymentTokenAddress = await paymentToken.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)
    // add allowance for payment in native token
    await execSafeTransaction(
      safe,
      await allowanceModule.setAllowance.populateTransaction(alice.address, paymentTokenAddress, 200, 0, 0),
      owner,
    )

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))
    expect(0).to.equal(await paymentToken.balanceOf(charlie.address))

    await execAllowanceTransfer(allowanceModule.connect(charlie), {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 99,
      spender: alice,
      paymentToken: paymentTokenAddress,
      payment: 200,
    })

    expect(await token.balanceOf(safeAddress)).to.equal(901)
    expect(await token.balanceOf(bob.address)).to.equal(99)
    expect(await paymentToken.balanceOf(safeAddress)).to.equal(800)
  })

  it('Revert when total of payment and transfer amount exceeds allowance', async () => {
    const { safe, allowanceModule, token, owner, alice, bob, charlie } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // add allowance
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))
    expect(0).to.equal(await token.balanceOf(charlie.address))

    await expect(
      execAllowanceTransfer(allowanceModule.connect(charlie), {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 100,
        spender: alice,
        paymentToken: tokenAddress,
        payment: 1,
      }),
    ).to.be.revertedWith('newSpent > paymentAllowance.spent && newSpent <= paymentAllowance.amount')

    expect(await token.balanceOf(safeAddress)).to.equal(1000)
    expect(await token.balanceOf(bob.address)).to.equal(0)
    expect(await token.balanceOf(charlie.address)).to.equal(0)
  })
})
