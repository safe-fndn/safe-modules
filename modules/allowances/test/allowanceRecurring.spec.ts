import { mine } from '@nomicfoundation/hardhat-network-helpers'
import { expect } from 'chai'

import execAllowanceTransfer from './test-helpers/execAllowanceTransfer'
import execSafeTransaction from './test-helpers/execSafeTransaction'
import setup from './test-helpers/setup'
import { deployments } from 'hardhat'

describe('AllowanceModule allowanceRecurring', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    return setup(deployments)
  })

  function nowInMinutes() {
    return Math.floor(Date.now() / (1000 * 60))
  }

  function calculateResetLast(base: number, period: number, now: number = nowInMinutes()) {
    return now - ((now - base) % period)
  }

  it('Execute allowance without refund', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    const configResetPeriod = 60 * 24
    const configResetBase = nowInMinutes() - 30

    // the very first resetLast produced by the contract
    // i.e., before the first period is elapsed, and
    // the contract updates/resets allowance
    const firstResetLast = calculateResetLast(configResetBase, configResetPeriod)

    await execSafeTransaction(
      safe,
      await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, configResetPeriod, configResetBase),
      owner,
    )
    // load an existing allowance
    let [amount, spent, resetPeriod, resetLast, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(configResetPeriod).to.equal(resetPeriod)
    expect(firstResetLast).to.equal(resetLast) // this should be set to inti time
    expect(1).to.equal(nonce)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(bob.address))

    // transfer 60 bucks to bob
    await execAllowanceTransfer(allowanceModule, {
      safe: await safe.getAddress(),
      token: tokenAddress,
      to: bob.address,
      amount: 60,
      spender: alice,
    })

    expect(940).to.equal(await token.balanceOf(safeAddress))
    expect(60).to.equal(await token.balanceOf(bob.address))

    // load alice's allowance
    ;[amount, spent, resetPeriod, resetLast, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(60).to.equal(spent)
    expect(configResetPeriod).to.equal(resetPeriod)
    expect(firstResetLast).to.equal(resetLast)
    expect(2).to.equal(nonce)

    // check that it fails over limit
    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: await safe.getAddress(),
        token: tokenAddress,
        to: bob.address,
        amount: 45,
        spender: alice,
      }),
    ).to.be.reverted

    await execAllowanceTransfer(allowanceModule, {
      safe: await safe.getAddress(),
      token: tokenAddress,
      to: bob.address,
      amount: 40,
      spender: alice,
    })
    expect(900).to.equal(await token.balanceOf(safeAddress))
    expect(100).to.equal(await token.balanceOf(bob.address))

    // go forward 12 hours (13 intervals with one hour between)
    await mine(13, { interval: 60 * 60 })

    // load alice's allowance, with less than resetPeriod elapsed: des not impact spend
    ;[amount, spent, resetPeriod, resetLast, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(100).to.equal(spent)
    expect(configResetPeriod).to.equal(resetPeriod)
    expect(firstResetLast).to.equal(resetLast)
    expect(3).to.equal(nonce)

    // however going forward 12 hours more (24 in total) should replenish
    await mine(13, { interval: 60 * 60 })
    ;[amount, spent, resetPeriod, resetLast, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // let's predict the next value calculated by the contract for lastReset
    const expectedLastReset = calculateResetLast(configResetBase, configResetPeriod, nowInMinutes() + 60 * 24)

    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(configResetPeriod).to.equal(resetPeriod)
    expect(expectedLastReset).to.be.equal(resetLast)
    expect(3).to.equal(nonce)

    // lets execute on the replenished allowance
    await execAllowanceTransfer(allowanceModule, {
      safe: await safe.getAddress(),
      token: tokenAddress,
      to: bob.address,
      amount: 45,
      spender: alice,
    })
    expect(855).to.equal(await token.balanceOf(safeAddress))
    expect(145).to.equal(await token.balanceOf(bob.address))
    ;[amount, spent, resetPeriod, resetLast, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    expect(100).to.equal(amount)
    expect(45).to.equal(spent)
    expect(configResetPeriod).to.equal(resetPeriod)
    expect(expectedLastReset).to.be.equal(resetLast)
    expect(4).to.equal(nonce)
  })

  it('Reverts when trying to set up a recurring allowance with reset period of 0', async () => {
    const { safe, allowanceModule, token, owner, alice } = await setupTests()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    const configResetPeriod = 0
    const configResetBase = nowInMinutes()

    await expect(
      execSafeTransaction(
        safe,
        await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, configResetPeriod, configResetBase),
        owner,
      ),
    ).to.be.reverted
  })
})
