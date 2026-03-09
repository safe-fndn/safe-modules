import { expect } from 'chai'
import { BigNumberish, BytesLike } from 'ethers'
import { deployments, ethers } from 'hardhat'

import { Account } from '../utils/p256'

describe('DaimoP256Verifier', function () {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { DaimoP256Verifier } = await deployments.fixture()

    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)

    async function verifySignature(message: BytesLike, r: BigNumberish, s: BigNumberish, x: BigNumberish, y: BigNumberish) {
      const coder = ethers.AbiCoder.defaultAbiCoder()
      return await verifier.fallback!.staticCall({
        data: coder.encode(['bytes32', 'uint256', 'uint256', 'uint256', 'uint256'], [message, r, s, x, y]),
      })
    }

    const account = new Account()

    return { verifier, verifySignature, account }
  })

  const SUCCESS = `0x${'00'.repeat(31)}01`
  const FAILURE = ethers.ZeroHash

  it('Should return 1 on valid signature', async function () {
    const { verifySignature, account } = await setupTests()

    const message = ethers.id('hello world')
    const { r, s } = account.sign(message)
    const { x, y } = account.publicKey

    expect(await verifySignature(message, r, s, x, y)).to.equal(SUCCESS)
  })

  it('Should ignore signature malleability', async function () {
    const { verifySignature, account } = await setupTests()

    const message = ethers.id('hello world')
    const { r, highS } = account.sign(message)
    const { x, y } = account.publicKey

    expect(await verifySignature(message, r, highS, x, y)).to.equal(SUCCESS)
  })

  it('Should return empty on unverified signature', async function () {
    const { verifySignature, account } = await setupTests()

    const { x, y } = account.publicKey

    expect(await verifySignature(ethers.ZeroHash, 1, 2, x, y)).to.equal(FAILURE)
  })

  it('Should return empty on invalid signature parameters', async function () {
    const { verifySignature, account } = await setupTests()

    const message = ethers.id('hello world')
    const { r, s } = account.sign(message)
    const { x, y } = account.publicKey

    // `r` and `s` must be in the range `[1, n)`, where `n` is the order of the curve.
    expect(await verifySignature(message, 0, s, x, y)).to.equal(FAILURE)
    expect(await verifySignature(message, r, 0, x, y)).to.equal(FAILURE)
    expect(await verifySignature(message, ethers.MaxUint256, s, x, y)).to.equal(FAILURE)
    expect(await verifySignature(message, r, ethers.MaxUint256, x, y)).to.equal(FAILURE)
  })

  it('Should return empty on invalid public key', async function () {
    const { verifySignature, account } = await setupTests()

    const message = ethers.id('hello world')
    const { r, s } = account.sign(message)
    const { x, y } = account.publicKey

    expect(await verifySignature(message, r, s, 0, y)).to.equal(FAILURE)
    expect(await verifySignature(message, r, s, x, 0)).to.equal(FAILURE)
  })

  it('Should return empty on invalid input', async function () {
    const { verifier } = await setupTests()

    expect(await verifier.fallback!.staticCall({ data: ethers.hexlify(ethers.toUtf8Bytes('invalid input')) })).to.equal(FAILURE)
  })
})
