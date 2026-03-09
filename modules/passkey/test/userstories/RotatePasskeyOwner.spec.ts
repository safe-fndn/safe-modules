// Import necessary dependencies from chai, hardhat, @safe-global/safe-4337, webauthn
import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey } from '../../src/utils/webauthn'
import {
  buildSafeUserOpTransaction,
  buildPackedUserOperationFromSafeUserOperation,
  signSafeOp,
} from '@safe-global/safe-4337/dist/src/utils/userOp'
import { buildSignatureBytes } from '@safe-global/safe-4337/dist/src/utils/execution'
import { chainId } from '../utils/hardhat'

/**
 * User story: Rotate passkey owner
 * In the setup, deploy a Safe with an EOA and a passkey signer as owners with threshold 1.
 * In the test, the EOA executes a userOp to swap the passkey signer with a new passkey signer.
 *
 * The flow can be summarized as follows:
 * Step 1: Setup the contracts
 * Step 2: Create a userOp to swap the passkey signer, sign it with EOA wallet
 * Step 3: Execute the userOp to swap the passkey signer
 */
describe('Rotate passkey owner [@userstory]', () => {
  // Create a fixture to setup the contracts and signer(s)
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { EntryPoint, Safe4337Module, SafeProxyFactory, SafeModuleSetup, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory } =
      await deployments.run()

    // EOA which will be the owner of the Safe
    const [user] = await ethers.getSigners()

    const entryPoint = await ethers.getContractAt('IEntryPoint', EntryPoint.address)
    const module = await ethers.getContractAt(Safe4337Module.abi, Safe4337Module.address)
    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const safeModuleSetup = await ethers.getContractAt(SafeModuleSetup.abi, SafeModuleSetup.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    // Create a WebAuthn credential for the initial signer
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

    const publicKey = decodePublicKey(credential.response)
    await signerFactory.createSigner(publicKey.x, publicKey.y, DaimoP256Verifier.address)
    const signer = await signerFactory.getSigner(publicKey.x, publicKey.y, DaimoP256Verifier.address)

    // The initializer data to enable the Safe4337Module as a module on a Safe
    const initializer = safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]])

    // Create setup data to deploy a Safe with EOA and passkey signer as owners, threshold 1, Safe4337Module as module and fallback handler
    const setupData = singleton.interface.encodeFunctionData('setup', [
      [user.address, signer],
      1n,
      safeModuleSetup.target,
      initializer,
      module.target,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])

    // Deploy a Safe with EOA and passkey signer as owners
    const safeSalt = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton, setupData, safeSalt)
    await proxyFactory.createProxyWithNonce(singleton, setupData, safeSalt)

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
      signer,
      credential,
      safeAddress,
    }
  })

  it('should execute a userOp with replaced WebAuthn signer as Safe owner', async () => {
    // Step 1: Setup the contracts
    const { user, module, entryPoint, verifier, navigator, SafeL2, signer, signerFactory, safeAddress } = await setupTests()
    const verifierAddress = await verifier.getAddress()

    // Check the owners of the created Safe
    const safeInstance = await ethers.getContractAt(SafeL2.abi, safeAddress)
    expect(await safeInstance.getOwners()).to.deep.equal([user.address, signer])

    // Step 2: Create a userOp to swap the passkey signer, sign it with EOA wallet

    // Create a new WebAuthn credential for the new signer
    const credentialNew = navigator.credentials.create({
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

    const publicKeyNew = decodePublicKey(credentialNew.response)
    await signerFactory.createSigner(publicKeyNew.x, publicKeyNew.y, verifierAddress)
    const signerNew = await signerFactory.getSigner(publicKeyNew.x, publicKeyNew.y, verifierAddress)

    const data = safeInstance.interface.encodeFunctionData('swapOwner', [user.address, signer, signerNew])

    // Build SafeOp
    const safeOpSwapSigner = buildSafeUserOpTransaction(
      safeAddress,
      safeAddress,
      0,
      data,
      await entryPoint.getNonce(safeAddress, 0),
      await entryPoint.getAddress(),
      false,
      true,
      {
        verificationGasLimit: 500000,
      },
    )

    // EOA wallet signs the userOp to swap the Passkey signer
    const signatureSwapSigner = buildSignatureBytes([await signSafeOp(user, await module.getAddress(), safeOpSwapSigner, await chainId())])

    const packedUserOpSwapSigner = buildPackedUserOperationFromSafeUserOperation({
      safeOp: safeOpSwapSigner,
      signature: signatureSwapSigner,
    })

    // Step 3: Execute the userOp to swap the passkey signer

    // Send 1 ETH to the Safe
    await user.sendTransaction({ to: safeAddress, value: ethers.parseEther('1') })

    await entryPoint.handleOps([packedUserOpSwapSigner], user.address)

    // Check if new signer is a Safe owner
    expect(await safeInstance.getOwners()).to.deep.equal([user.address, signerNew])
  })
})
