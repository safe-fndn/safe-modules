import { expect } from 'chai'
import { parseUnits, ZeroAddress } from 'ethers'
import hre, { deployments } from 'hardhat'

import execAllowanceTransfer from './test-helpers/execAllowanceTransfer'
import execSafeTransaction from './test-helpers/execSafeTransaction'
import setup from './test-helpers/setup'

const OneEther = parseUnits('1', 'ether')

describe('AllowanceModule allowanceSingle', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    return setup(deployments)
  })

  it('Execute allowance with delegate', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.not.equal(lastReset) // this should be set to init time
    expect(1).to.equal(nonce)

    // load an non existing allowance - bob has none
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, bob.address, tokenAddress)
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(0).to.equal(nonce)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: tokenAddress,
      to: bob.address,
      amount: 60,
      spender: alice,
    })

    expect(940).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(60).to.equal(await token.balanceOf(bob.address))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to be reflected
    expect(100).to.equal(amount)
    expect(60).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(2).to.equal(nonce)

    // remove Alice's as spender
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)

    // load Alice's Allowance after delegate removal
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // everything zeroed, except nonce
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(2).to.equal(nonce)
  })

  it('Execute allowance with delegate and empty signature', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.not.equal(lastReset) // this should be set to init time
    expect(1).to.equal(nonce)

    // load an non existing allowance - bob has none
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, bob.address, tokenAddress)
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(0).to.equal(nonce)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await allowanceModule.connect(alice).executeAllowanceTransfer(safe, token, bob.address, 60, ZeroAddress, 0, alice.address, '0x')

    expect(940).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(60).to.equal(await token.balanceOf(bob.address))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to be reflected
    expect(100).to.equal(amount)
    expect(60).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(2).to.equal(nonce)

    // remove Alice's as spender
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)

    // load Alice's Allowance after delegate removal
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // everything zeroed, except nonce
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(2).to.equal(nonce)
  })

  it('Execute allowance with v=1 in signature', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.not.equal(lastReset) // this should be set to init time
    expect(1).to.equal(nonce)

    // load an non existing allowance - bob has none
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, bob.address, tokenAddress)
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(0).to.equal(nonce)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await allowanceModule
      .connect(alice)
      .executeAllowanceTransfer(safe, token, bob.address, 60, ZeroAddress, 0, alice.address, `0x${'00'.repeat(64)}01`)

    expect(940).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(60).to.equal(await token.balanceOf(bob.address))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to be reflected
    expect(100).to.equal(amount)
    expect(60).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(2).to.equal(nonce)

    // remove Alice's as spender
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)

    // load Alice's Allowance after delegate removal
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // everything zeroed, except nonce
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(2).to.equal(nonce)
  })

  it('Execute allowance using eth_sign', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    const allowanceAddress = await allowanceModule.getAddress()

    expect(await safe.isModuleEnabled(allowanceAddress)).to.equal(true)

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(100).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.not.equal(lastReset) // this should be set to init time
    expect(1).to.equal(nonce)

    // load an non existing allowance - bob has none
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, bob.address, tokenAddress)
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(0).to.equal(nonce)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    const transferHashData = await allowanceModule.generateTransferHash(safeAddress, tokenAddress, bob.address, 60, ZeroAddress, 0, 1)

    const signature = await alice.signMessage(hre.ethers.getBytes(transferHashData))

    await allowanceModule
      .connect(alice)
      .executeAllowanceTransfer(
        safe,
        token,
        bob.address,
        60,
        ZeroAddress,
        0,
        alice.address,
        signature.replace(/1b$/, '1f').replace(/1c$/, '20'),
      )

    expect(940).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(60).to.equal(await token.balanceOf(bob.address))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to be reflected
    expect(100).to.equal(amount)
    expect(60).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(2).to.equal(nonce)

    // remove Alice's as spender
    await execSafeTransaction(safe, await allowanceModule.removeDelegate.populateTransaction(alice.address, true), owner)

    // load Alice's Allowance after delegate removal
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // everything zeroed, except nonce
    expect(0).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.equal(lastReset)
    expect(2).to.equal(nonce)
  })

  it('Execute multiple ether allowance with delegate', async () => {
    const { provider } = hre.ethers
    const { safe, allowanceModule, owner, alice } = await setupTests()

    const safeAddress = await safe.getAddress()

    // fund the safe
    await owner.sendTransaction({
      to: safeAddress,
      value: OneEther,
    })

    /*
     * Safe will contain 1 ETH
     * Alice configured as ETH spender in Allowance
     * Bob not configured as spender in any Allowance
     *
     * Alice sends to Bob
     */
    const bob = '0x0000000000000000000000000000000000abcdef'

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(
      safe,
      await allowanceModule.setAllowance.populateTransaction(
        alice.address,
        ZeroAddress, // zero means ether
        OneEther,
        0,
        0,
      ),
      owner,
    )

    // load an existing allowance
    let [amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, ZeroAddress)
    expect(OneEther).to.equal(amount)
    expect(0).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(0).to.not.equal(lastReset) // this should be set to inti time
    expect(1).to.equal(nonce)

    expect(OneEther).to.equal(await provider.getBalance(safeAddress))
    expect(0).to.equal(await provider.getBalance(bob))

    // send 0.001 to bob using alice's allowance
    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: ZeroAddress,
      to: bob,
      amount: parseUnits('0.001', 'ether'),
      spender: alice,
    })

    expect(parseUnits('0.999', 'ether')).to.equal(await provider.getBalance(safeAddress))
    expect(parseUnits('0.001', 'ether')).to.equal(await provider.getBalance(bob))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, ZeroAddress)

    // expect the last transfer to be reflected
    expect(parseUnits('1', 'ether')).to.equal(amount)
    expect(parseUnits('0.001', 'ether')).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(2).to.equal(nonce)

    // send 0.001 more
    await execAllowanceTransfer(allowanceModule, {
      safe: safeAddress,
      token: ZeroAddress,
      to: bob,
      amount: parseUnits('0.001', 'ether'),
      spender: alice,
    })

    expect(parseUnits('0.998', 'ether')).to.equal(await provider.getBalance(safeAddress))
    expect(parseUnits('0.002', 'ether')).to.equal(await provider.getBalance(bob))

    // load Alice's Allowance
    ;[amount, spent, minReset, lastReset, nonce] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, ZeroAddress)

    // expect the last transfer to be reflected
    expect(parseUnits('1', 'ether')).to.equal(amount)
    expect(parseUnits('0.002', 'ether')).to.equal(spent)
    expect(0).to.equal(minReset)
    expect(lastReset > 0).to.be.true
    expect(3).to.equal(nonce)
  })

  it('Reverts when ether transfer fails', async () => {
    const { provider } = hre.ethers
    const { safe, allowanceModule, owner, alice } = await setupTests()

    const safeAddress = await safe.getAddress()

    // fund the safe
    await owner.sendTransaction({
      to: safeAddress,
      value: OneEther,
    })

    /*
     * Safe will contain 1 ETH
     * Alice configured as ETH spender in Allowance
     * Bob not configured as spender in any Allowance
     *
     * Alice sends to Bob
     */
    const bob = '0x0000000000000000000000000000000000abcdef'

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(
      safe,
      await allowanceModule.setAllowance.populateTransaction(
        alice.address,
        ZeroAddress, // zero means ether
        hre.ethers.parseEther('2'),
        0,
        0,
      ),
      owner,
    )

    // load an existing allowance
    let [amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, ZeroAddress)
    expect(hre.ethers.parseEther('2')).to.equal(amount)
    expect(OneEther).to.equal(await provider.getBalance(safeAddress))
    expect(0).to.equal(await provider.getBalance(bob))

    // send 0.001 to bob using alice's allowance
    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: ZeroAddress,
        to: bob,
        amount: parseUnits('2', 'ether'),
        spender: alice,
      }),
    ).to.be.revertedWith('Could not execute ether transfer')

    expect(parseUnits('1', 'ether')).to.equal(await provider.getBalance(safeAddress))
    expect(parseUnits('0', 'ether')).to.equal(await provider.getBalance(bob))

    // load Alice's Allowance
    ;[amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, ZeroAddress)

    expect(parseUnits('2', 'ether')).to.equal(amount)
    expect(parseUnits('0', 'ether')).to.equal(spent)
  })

  it('Reverts when token transfer fails', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 2000, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(2000).to.equal(amount)
    expect(0).to.equal(spent)

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 2000,
        spender: alice,
      }),
    ).to.be.revertedWith('Could not execute token transfer')

    expect(1000).to.equal(await token.balanceOf(safeAddress))
    expect(0).to.equal(await token.balanceOf(alice.address))
    expect(0).to.equal(await token.balanceOf(bob.address))

    // load Alice's Allowance
    ;[amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to not be reflected
    expect(2000).to.equal(amount)
    expect(0).to.equal(spent)
  })

  it('Reverts when token transfer fails without reverting', async () => {
    const { safe, allowanceModule, owner, alice, bob } = await setupTests()

    // Deploy a token that returns `false` on failed transfers instead of reverting.
    const token = await hre.ethers.deployContract('WeirdToken')

    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()

    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 2000, 0, 0), owner)

    // ensure delegates are well configured
    const { results } = await allowanceModule.getDelegates(safeAddress, 0, 10)
    expect(results).to.deep.equal([alice.address])

    // ensure tokens from allowances are correct
    expect(await allowanceModule.getTokens(safeAddress, alice.address)).to.deep.equal([tokenAddress])

    // load an existing allowance
    let [amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)
    expect(2000).to.equal(amount)
    expect(0).to.equal(spent)

    await expect(
      execAllowanceTransfer(allowanceModule, {
        safe: safeAddress,
        token: tokenAddress,
        to: bob.address,
        amount: 2000,
        spender: alice,
      }),
    ).to.be.revertedWith('Could not execute token transfer')

    // load Alice's Allowance
    ;[amount, spent, , ,] = await allowanceModule.getTokenAllowance(safeAddress, alice.address, tokenAddress)

    // expect the last transfer to not be reflected
    expect(2000).to.equal(amount)
    expect(0).to.equal(spent)
  })

  it('Reverts when using smart contract signature scheme', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()
    const tokenAddress = await token.getAddress()
    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)
    await expect(
      allowanceModule.executeAllowanceTransfer(safe, token, bob.address, 60, ZeroAddress, 0, alice.address, `0x${'00'.repeat(65)}`),
    ).to.be.revertedWith('Contract signatures are not supported by this module')
  })

  it('Reverts on invalid signature', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()
    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    const transferHashData = await allowanceModule.generateTransferHash(safeAddress, tokenAddress, bob.address, 60, ZeroAddress, 0, 1)
    const signature = await bob.signMessage(hre.ethers.getBytes(transferHashData))

    await expect(
      allowanceModule.executeAllowanceTransfer(
        safe,
        token,
        bob.address,
        60,
        ZeroAddress,
        0,
        alice.address,
        signature.replace(/1b$/, '1f').replace(/1c$/, '20'),
      ),
    ).to.be.revertedWith('expectedDelegate == signer && delegates[address(safe)][uint48(signer)].delegate == signer')
  })

  it('Reverts on invalid signature length', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()
    const safeAddress = await safe.getAddress()
    const tokenAddress = await token.getAddress()
    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    const transferHashData = await allowanceModule.generateTransferHash(safeAddress, tokenAddress, bob.address, 60, ZeroAddress, 0, 1)
    const signature = await alice.signMessage(hre.ethers.getBytes(transferHashData))

    await expect(
      allowanceModule.executeAllowanceTransfer(
        safe,
        token,
        bob.address,
        60,
        ZeroAddress,
        0,
        alice.address,
        `${signature.replace(/1b$/, '1f').replace(/1c$/, '20')}${'00'.repeat(65)}`,
      ),
    ).to.be.revertedWith('signatures.length == 65')
  })

  it('Reverts if ecrecover fails', async () => {
    const { safe, allowanceModule, token, owner, alice, bob } = await setupTests()
    const tokenAddress = await token.getAddress()
    // add alice as delegate
    await execSafeTransaction(safe, await allowanceModule.addDelegate.populateTransaction(alice.address), owner)

    // create an allowance for alice
    await execSafeTransaction(safe, await allowanceModule.setAllowance.populateTransaction(alice.address, tokenAddress, 100, 0, 0), owner)

    await expect(
      allowanceModule.executeAllowanceTransfer(safe, token, bob.address, 60, ZeroAddress, 0, alice.address, `0x${'00'.repeat(64)}1f`),
    ).to.be.revertedWith('owner != address(0)')
  })
})
