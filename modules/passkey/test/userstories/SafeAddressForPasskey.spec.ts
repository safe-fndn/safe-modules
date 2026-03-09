import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'

import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey } from '../../src/utils/webauthn'

/**
 * User story: Find Safe for Passkey
 * This user story demonstrates how to compute the address of a Safe deterministically for a given
 * WebAuthn credential. Note that searching for Safes by owner is not really practical without a
 * service (as building Safe owners from Ethereum logs is non-trivial). Instead we show that, given
 * a Dapp-specific initial Safe setup with a passkey owner, it is possible to find the Safe address
 * corresponding to the passkey.
 */
describe('Safe Address for Passkey [@userstory]', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { SafeProxyFactory, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory, SafeWebAuthnSharedSigner } = await deployments.run()

    const safeProxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const safeSingleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)
    const sharedSigner = await ethers.getContractAt('SafeWebAuthnSharedSigner', SafeWebAuthnSharedSigner.address)
    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)

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

    const signerConfig = {
      ...decodePublicKey(credential.response),
      verifiers: ethers.solidityPacked(['uint16', 'address'], [0, await verifier.getAddress()]),
    }

    const deploySafe = async ({ initializer, saltNonce }: { initializer: string; saltNonce: bigint }) => {
      const safeAddress = await safeProxyFactory.createProxyWithNonce.staticCall(safeSingleton, initializer, saltNonce)
      await safeProxyFactory.createProxyWithNonce(safeSingleton, initializer, saltNonce)
      return await ethers.getContractAt(SafeL2.abi, safeAddress)
    }

    return {
      safeSingleton,
      safeProxyFactory,
      signerFactory,
      sharedSigner,
      signerConfig,
      deploySafe,
    }
  })

  it('should compute the Safe address owned by a WebAuthn proxy signer', async () => {
    const { safeSingleton, safeProxyFactory, signerFactory, signerConfig, deploySafe } = await setupTests()

    await signerFactory.getSigner(signerConfig.x, signerConfig.y, signerConfig.verifiers)
    const signer = await ethers.getContractAt(
      'SafeWebAuthnSignerSingleton',
      await signerFactory.getSigner(signerConfig.x, signerConfig.y, signerConfig.verifiers),
    )

    const initializer = safeSingleton.interface.encodeFunctionData('setup', [
      [await signer.getAddress()],
      1,
      ethers.ZeroAddress,
      '0x',
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const saltNonce = 42n

    const safe = await deploySafe({ initializer, saltNonce })
    const deterministicSafeAddress = ethers.getCreate2Address(
      await safeProxyFactory.getAddress(),
      ethers.solidityPackedKeccak256(['bytes32', 'uint256'], [ethers.keccak256(initializer), saltNonce]),
      ethers.solidityPackedKeccak256(
        ['bytes', 'bytes'],
        [
          await safeProxyFactory.proxyCreationCode(),
          ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await safeSingleton.getAddress()]),
        ],
      ),
    )

    expect(deterministicSafeAddress).to.equal(await safe.getAddress())
  })

  it('should compute the Safe address owned by a WebAuthn shared signer', async () => {
    const { safeSingleton, safeProxyFactory, sharedSigner, signerConfig, deploySafe } = await setupTests()

    const initializer = safeSingleton.interface.encodeFunctionData('setup', [
      [await sharedSigner.getAddress()],
      1,
      await sharedSigner.getAddress(),
      sharedSigner.interface.encodeFunctionData('configure', [signerConfig]),
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const saltNonce = 42n

    const safe = await deploySafe({ initializer, saltNonce })
    const deterministicSafeAddress = ethers.getCreate2Address(
      await safeProxyFactory.getAddress(),
      ethers.solidityPackedKeccak256(['bytes32', 'uint256'], [ethers.keccak256(initializer), saltNonce]),
      ethers.solidityPackedKeccak256(
        ['bytes', 'bytes'],
        [
          await safeProxyFactory.proxyCreationCode(),
          ethers.AbiCoder.defaultAbiCoder().encode(['address'], [await safeSingleton.getAddress()]),
        ],
      ),
    )

    expect(deterministicSafeAddress).to.equal(await safe.getAddress())
  })

  it('should search for Safes owned by a WebAuthn shared signer', async () => {
    const { safeSingleton, sharedSigner, signerConfig, deploySafe } = await setupTests()

    const safe = await deploySafe({
      initializer: safeSingleton.interface.encodeFunctionData('setup', [
        [await sharedSigner.getAddress()],
        1,
        await sharedSigner.getAddress(),
        sharedSigner.interface.encodeFunctionData('configure', [signerConfig]),
        ethers.ZeroAddress,
        ethers.ZeroAddress,
        0,
        ethers.ZeroAddress,
      ]),
      saltNonce: 0n,
    })

    let foundSafeAddress = null

    const publicKeyHash = ethers.solidityPackedKeccak256(['uint256', 'uint256'], [signerConfig.x, signerConfig.y])
    const configuredSafes = await ethers.provider.getLogs({
      topics: sharedSigner.interface.encodeFilterTopics('SafeWebAuthnSharedSignerConfigured', [publicKeyHash]),
      fromBlock: 0,
    })
    for (const { address: possibleSafeAddress } of configuredSafes) {
      const possibleSafe = safeSingleton.attach(possibleSafeAddress) as typeof safeSingleton

      const { x, y } = await sharedSigner.getConfiguration(possibleSafe)
      const isOwner = await possibleSafe.isOwner(sharedSigner)

      if (signerConfig.x === x && signerConfig.y === y && isOwner) {
        foundSafeAddress = possibleSafe
        break
      }
    }

    expect(foundSafeAddress).to.equal(await safe.getAddress())
  })
})
