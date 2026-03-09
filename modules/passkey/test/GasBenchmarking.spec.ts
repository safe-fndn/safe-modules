import { expect } from 'chai'
import { deployments, ethers, network } from 'hardhat'

import * as ERC1271 from './utils/erc1271'
import { WebAuthnCredentials } from '../test/utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../src/utils/webauthn'
import { IP256Verifier } from '../typechain-types'

describe('Gas Benchmarking [@bench]', function () {
  const navigator = {
    credentials: new WebAuthnCredentials(),
  }
  const credential = navigator.credentials.create({
    publicKey: {
      rp: {
        name: 'Safe',
        id: 'safe.global',
      },
      user: {
        id: ethers.getBytes(ethers.id('chucknorris')),
        name: 'chucknorris',
        displayName: 'Chuck Norris',
      },
      challenge: ethers.toBeArray(Date.now()),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    },
  })

  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { DaimoP256Verifier, SafeWebAuthnSignerFactory } = await deployments.fixture()

    const Benchmarker = await ethers.getContractFactory('Benchmarker')
    const benchmarker = await Benchmarker.deploy()

    const factory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)

    const DummyP256Verifier = await ethers.getContractFactory('DummyP256Verifier')
    const verifiersConfig = {
      daimo: [0, await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)],
      dummy: [0, await DummyP256Verifier.deploy()],
      precompile: [0x0100, null],
    } as Record<string, [number, IP256Verifier | null]>

    return { benchmarker, factory, verifiersConfig }
  })

  describe('SafeWebAuthnSignerProxy', () => {
    it(`Benchmark signer deployment cost`, async function () {
      const { benchmarker, factory } = await setupTests()

      const { x, y } = decodePublicKey(credential.response)
      const verifier = `0x${'ee'.repeat(20)}`

      const [gas] = await benchmarker.call.staticCall(factory, factory.interface.encodeFunctionData('createSigner', [x, y, verifier]))

      console.log(`      ⛽ deployment: ${gas}`)
    })

    for (const [name, key, networkName] of [
      ['Daimo', 'daimo', null],
      ['Dummy', 'dummy', null],
      ['Precompile', 'precompile', 'localhost'],
    ] as [string, string, string | null][]) {
      it(`Benchmark signer verification cost with ${name} verifier`, async function () {
        if (networkName && network.name !== networkName) {
          this.skip()
        }

        const { benchmarker, verifiersConfig, factory } = await setupTests()

        const challenge = ethers.id('hello world')
        const assertion = navigator.credentials.get({
          publicKey: {
            challenge: ethers.getBytes(challenge),
            rpId: 'safe.global',
            allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
            userVerification: 'required',
          },
        })

        const { x, y } = decodePublicKey(credential.response)
        const [precompile, verifier] = verifiersConfig[key]
        const verifiers = ethers.solidityPacked(['uint16', 'address'], [precompile, (await verifier?.getAddress()) ?? ethers.ZeroAddress])

        await factory.createSigner(x, y, verifiers)
        const signer = await ethers.getContractAt('SafeWebAuthnSignerSingleton', await factory.getSigner(x, y, verifiers))
        const signature = encodeWebAuthnSignature(assertion.response)

        const [gas, returnData] = await benchmarker.call.staticCall(
          signer,
          signer.interface.encodeFunctionData('isValidSignature(bytes32,bytes)', [challenge, signature]),
        )

        const [magicValue] = ethers.AbiCoder.defaultAbiCoder().decode(['bytes4'], returnData)
        expect(magicValue).to.equal(ERC1271.MAGIC_VALUE)

        console.log(`      ⛽ verification (${name}): ${gas}`)
      })
    }
  })
})
