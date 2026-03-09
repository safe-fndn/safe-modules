import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey } from '../../src/utils/webauthn'

/**
 * User story: Deterministic passkey signer address
 * This user story test documents how the {SafeWebAuthnSignerProxy} can be pre-computed so that it
 * can be used for counterfactual deployments.
 */
describe('Deterministic passkey signer address [@userstory]', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { DaimoP256Verifier, SafeWebAuthnSignerFactory } = await deployments.run()

    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    return {
      module,
      signerFactory,
      navigator,
      verifier,
    }
  })

  it('should execute a userOp with replaced WebAuthn signer as Safe owner', async () => {
    const { verifier, signerFactory, navigator } = await setupTests()

    // Step 1: Create the WebAuthn credential for the passkey signer
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

    // Step 2: Compute signer configuration
    const publicKey = decodePublicKey(credential.response)
    const p256Precompile = ethers.ZeroAddress // precompile disabled
    const verifiers = BigInt(ethers.solidityPacked(['uint16', 'address'], [p256Precompile, await verifier.getAddress()]))

    // Step 3: Compute the deterministic address for the passkey signer
    const SafeWebAuthnSignerProxy = await ethers.getContractFactory('SafeWebAuthnSignerProxy')
    const { data } = await SafeWebAuthnSignerProxy.getDeployTransaction(
      await signerFactory.SINGLETON(),
      publicKey.x,
      publicKey.y,
      verifiers,
    )
    const signerAddress = ethers.getCreate2Address(await signerFactory.getAddress(), ethers.ZeroHash, ethers.keccak256(data))

    // Check:
    // 1. the computed address matches the address reported by the signer factory
    // 2. there is no code deployed at the signer address
    // 3. that the signer factory deploys a signer at that address
    expect(await signerFactory.getSigner(publicKey.x, publicKey.y, verifiers)).to.equal(signerAddress)
    expect(await ethers.provider.getCode(signerAddress)).to.equal('0x')
    await expect(signerFactory.createSigner(publicKey.x, publicKey.y, verifiers)).to.not.be.reverted
    expect(await ethers.provider.getCode(signerAddress)).to.not.equal('0x')
  })
})
