// Import necessary dependencies from chai, hardhat, @safe-global/safe-4337, webauthn
import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../src/utils/webauthn'
import { buildSafeUserOpTransaction, buildPackedUserOperationFromSafeUserOperation } from '@safe-global/safe-4337/src/utils/userOp'
import { buildSignatureBytes } from '@safe-global/safe-4337/src/utils/execution'

/**
 * User story: Create a Safe with Passkey signer as owner
 * The test case here deploys a Safe with a passkey signer as the only owner.
 *
 * The flow can be summarized as follows:
 * Step 1: Setup the contracts.
 * Step 2: Create a userOp, sign it with Passkey signer.
 * Step 3: Execute the userOp that deploys a safe with passkey signer as owner.
 */
describe('Create a Safe with Passkey signer as owner: [@userstory]', () => {
  // Create a fixture to setup the contracts and signer(s)
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { EntryPoint, Safe4337Module, SafeProxyFactory, SafeModuleSetup, SafeL2, FCLP256Verifier, SafeWebAuthnSignerFactory } =
      await deployments.run()

    const [user] = await ethers.getSigners()

    const entryPoint = await ethers.getContractAt('IEntryPoint', EntryPoint.address)
    const module = await ethers.getContractAt(Safe4337Module.abi, Safe4337Module.address)
    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const safeModuleSetup = await ethers.getContractAt(SafeModuleSetup.abi, SafeModuleSetup.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const verifier = await ethers.getContractAt('IP256Verifier', FCLP256Verifier.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    // Create a WebAuthn credential for the signer
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

    return {
      user,
      proxyFactory,
      safeModuleSetup,
      module,
      entryPoint,
      singleton,
      signerFactory,
      navigator,
      verifier,
      SafeL2,
      credential,
    }
  })

  it('should execute a userOp with WebAuthn signer as owner', async () => {
    // Step 1: Setup the contracts
    const { user, proxyFactory, safeModuleSetup, module, entryPoint, singleton, navigator, SafeL2, credential, signerFactory, verifier } =
      await setupTests()

    // Deploy a signer contract
    const publicKey = decodePublicKey(credential.response)
    // Deploy signer contract
    await signerFactory.createSigner(publicKey.x, publicKey.y, await verifier.getAddress())
    // Get signer address
    const signer = await signerFactory.getSigner(publicKey.x, publicKey.y, await verifier.getAddress())

    // Step 2: Create a userOp, sign it with Passkey signer.

    // The initializer data to enable the Safe4337Module as a module on a Safe
    const initializer = safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]])

    // Create setup data to deploy a Safe with EOA and passkey signer as owners, threshold 1, Safe4337Module as module and fallback handler
    const setupData = singleton.interface.encodeFunctionData('setup', [
      [signer],
      1n,
      safeModuleSetup.target,
      initializer,
      module.target,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])

    // Predict the Safe address to construct the userOp, generate
    const safeSalt = Date.now()
    const safe = await proxyFactory.createProxyWithNonce.staticCall(singleton, setupData, safeSalt)

    // Deploy data required in the initCode of the userOp
    const deployData = proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [singleton.target, setupData, safeSalt])

    const safeOp = buildSafeUserOpTransaction(
      safe,
      ethers.ZeroAddress,
      0,
      '0x',
      await entryPoint.getNonce(safe, 0),
      await entryPoint.getAddress(),
      false,
      true,
      {
        initCode: ethers.solidityPacked(['address', 'bytes'], [proxyFactory.target, deployData]),
        // Set a higher verificationGasLimit to avoid error "AA26 over verificationGasLimit"
        verificationGasLimit: 800000,
      },
    )

    const packedUserOp = buildPackedUserOperationFromSafeUserOperation({
      safeOp,
      signature: '0x',
    })

    // opHash that will be signed using Passkey credentials
    const opHash = await module.getOperationHash(packedUserOp)

    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(opHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })

    // Build the contract signature that a Safe will forward to the signer contract
    const signature = buildSignatureBytes([
      {
        signer: signer as string,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])

    // Set the signature in the packedUserOp
    packedUserOp.signature = ethers.solidityPacked(['uint48', 'uint48', 'bytes'], [safeOp.validAfter, safeOp.validUntil, signature])

    // Send 1 ETH to the Safe
    await user.sendTransaction({ to: safe, value: ethers.parseEther('1') })
    // Check if Safe is not already created
    expect(await ethers.provider.getCode(safe)).to.equal('0x')

    // Step 3: Execute the userOp that deploys a safe with passkey signer as owner.
    await entryPoint.handleOps([packedUserOp], user.address)

    // Check if Safe is created and uses the expected Singleton
    const [implementation] = ethers.AbiCoder.defaultAbiCoder().decode(['address'], await ethers.provider.getStorage(safe, 0))
    expect(implementation).to.equal(singleton.target)

    // Check if signer is the Safe owner
    const safeInstance = await ethers.getContractAt(SafeL2.abi, safe)
    expect(await safeInstance.getOwners()).to.deep.equal([signer])
  })
})
