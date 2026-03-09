import { setCode } from '@nomicfoundation/hardhat-toolbox/network-helpers'
import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'

import { Account } from '../utils/p256'
import { MockContract } from '../../typechain-types'

describe('P256', function () {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { DaimoP256Verifier } = await deployments.fixture()

    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)

    const precompileAddress = ethers.toBeHex(0x0100, 20)
    await setCode(precompileAddress, await ethers.provider.getCode(verifier))
    const precompile = await ethers.getContractAt('IP256Verifier', precompileAddress)

    const verifiers = BigInt(ethers.solidityPacked(['uint16', 'address'], [precompileAddress, DaimoP256Verifier.address]))
    const allVerifiers = [
      [precompileAddress, DaimoP256Verifier.address],
      [ethers.ZeroAddress, DaimoP256Verifier.address],
      [precompileAddress, ethers.ZeroAddress],
      [ethers.ZeroAddress, precompileAddress],
    ].map(([precompile, fallback]) => BigInt(ethers.solidityPacked(['uint16', 'address'], [precompile, fallback])))

    const P256Lib = await ethers.getContractFactory('TestP256Lib')
    const p256Lib = await P256Lib.deploy()

    const account = new Account()

    return { precompile, verifier, verifiers, allVerifiers, p256Lib, account }
  })

  describe('isValidSignature', function () {
    it('Should return true on valid signature', async function () {
      const { verifier, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, s } = account.sign(message)
      const { x, y } = account.publicKey

      expect(await p256Lib.verifySignature(verifier, message, r, s, x, y)).to.be.true
      expect(await p256Lib.verifySignatureAllowMalleability(verifier, message, r, s, x, y)).to.be.true
    })

    it('Should return false on invalid signature', async function () {
      const { verifier, p256Lib } = await setupTests()

      expect(await p256Lib.verifySignature(verifier, ethers.ZeroHash, 1, 2, 3, 4)).to.be.false
      expect(await p256Lib.verifySignatureAllowMalleability(verifier, ethers.ZeroHash, 1, 2, 3, 4)).to.be.false
    })

    it('Should check for signature signature malleability', async function () {
      const { verifier, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, highS } = account.sign(message)
      const { x, y } = account.publicKey

      expect(await p256Lib.verifySignature(verifier, message, r, highS, x, y)).to.be.false
      expect(await p256Lib.verifySignatureAllowMalleability(verifier, message, r, highS, x, y)).to.be.true
    })

    it('Should return false for misbehaving verifiers', async function () {
      const { p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, s } = account.sign(message)
      const { x, y } = account.publicKey

      const MockContract = await ethers.getContractFactory('MockContract')
      const mockVerifier = await MockContract.deploy()

      for (const configureMock of [
        // wrong return data length
        () => mockVerifier.givenAnyReturn(ethers.AbiCoder.defaultAbiCoder().encode(['bool', 'uint256'], [true, 42])),
        // invalid boolean value
        () => mockVerifier.givenAnyReturnUint(ethers.MaxUint256),
        // revert
        () => mockVerifier.givenAnyRevert(),
      ]) {
        await configureMock()
        expect(await p256Lib.verifySignature(mockVerifier, message, r, s, x, y)).to.be.false
        expect(await p256Lib.verifySignatureAllowMalleability(mockVerifier, message, r, s, x, y)).to.be.false
      }
    })
  })

  describe('isValidSignatureWithVerifiers', function () {
    it('Should handle all possible verifier configurations', async function () {
      const { allVerifiers, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, s } = account.sign(message)
      const { x, y } = account.publicKey

      for (const verifiers of allVerifiers) {
        expect(await p256Lib.verifySignatureWithVerifiers(verifiers, message, r, s, x, y)).to.be.true
        expect(await p256Lib.verifySignatureWithVerifiersAllowMalleability(verifiers, message, r, s, x, y)).to.be.true
      }
    })

    it('Should fallback to Solidity verifier when precompile fails', async function () {
      const { precompile, verifiers, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, s } = account.sign(message)
      const { x, y } = account.publicKey

      const MockContract = await ethers.getContractFactory('MockContract')
      const mock = await MockContract.deploy()
      await setCode(await precompile.getAddress(), await ethers.provider.getCode(mock))
      const mockPrecompile = await ethers.getContractAt('MockContract', precompile)

      for (const configureMock of [
        // wrong return data length
        () => mockPrecompile.givenAnyReturn(ethers.AbiCoder.defaultAbiCoder().encode(['bool', 'uint256'], [true, 42])),
        // invalid boolean value
        () => mockPrecompile.givenAnyReturnUint(ethers.MaxUint256),
        // revert
        () => mockPrecompile.givenAnyRevert(),
      ]) {
        await configureMock()
        expect(await p256Lib.verifySignatureWithVerifiers(verifiers, message, r, s, x, y)).to.be.true
        expect(await p256Lib.verifySignatureWithVerifiersAllowMalleability(verifiers, message, r, s, x, y)).to.be.true
      }
    })

    it('Should return false on invalid signature', async function () {
      const { allVerifiers, p256Lib } = await setupTests()

      for (const verifiers of allVerifiers) {
        expect(await p256Lib.verifySignatureWithVerifiers(verifiers, ethers.ZeroHash, 1, 2, 3, 4)).to.be.false
        expect(await p256Lib.verifySignatureWithVerifiersAllowMalleability(verifiers, ethers.ZeroHash, 1, 2, 3, 4)).to.be.false
      }
    })

    it('Should check for signature signature malleability', async function () {
      const { allVerifiers, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, highS } = account.sign(message)
      const { x, y } = account.publicKey

      for (const verifiers of allVerifiers) {
        expect(await p256Lib.verifySignatureWithVerifiers(verifiers, message, r, highS, x, y)).to.be.false
        expect(await p256Lib.verifySignatureWithVerifiersAllowMalleability(verifiers, message, r, highS, x, y)).to.be.true
      }
    })

    it('Should return false for misbehaving verifiers', async function () {
      const { precompile, p256Lib, account } = await setupTests()

      const message = ethers.id('hello passkeys')
      const { r, s } = account.sign(message)
      const { x, y } = account.publicKey

      const MockContract = await ethers.getContractFactory('MockContract')
      const mockVerifier = await MockContract.deploy()
      await setCode(await precompile.getAddress(), await ethers.provider.getCode(mockVerifier))
      const mockPrecompile = await ethers.getContractAt('MockContract', precompile)

      const verifiers = BigInt(ethers.solidityPacked(['uint16', 'address'], [mockPrecompile.target, mockVerifier.target]))

      const configurations = [
        // wrong return data length
        (m: MockContract) => m.givenAnyReturn(ethers.AbiCoder.defaultAbiCoder().encode(['bool', 'uint256'], [true, 42])),
        // invalid boolean value
        (m: MockContract) => m.givenAnyReturnUint(ethers.MaxUint256),
        // revert
        (m: MockContract) => m.givenAnyRevert(),
      ]
      for (const configurePrecompile of configurations) {
        for (const configureVerifier of configurations) {
          await configurePrecompile(mockPrecompile)
          await configureVerifier(mockVerifier)
          expect(await p256Lib.verifySignatureWithVerifiers(verifiers, message, r, s, x, y)).to.be.false
          expect(await p256Lib.verifySignatureWithVerifiersAllowMalleability(verifiers, message, r, s, x, y)).to.be.false
        }
      }
    })
  })
})
