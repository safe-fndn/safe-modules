import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../src/utils/webauthn'
import { buildSafeUserOpTransaction, buildPackedUserOperationFromSafeUserOperation } from '@safe-global/safe-4337/src/utils/userOp'
import { buildSignatureBytes } from '@safe-global/safe-4337/src/utils/execution'

/**
 * User story: Execute userOp from Passkey signer
 * The test case here deploys a Safe with a passkey signer as the only owner.
 * The passkey signer then signs a userOp and gets executed. The test case here assumes that a signer contract is already deployed.
 *
 * The flow can be summarized as follows:
 * Step 1: Setup the contracts.
 * Step 2: Create a userOp and sign it using passkey credential.
 * Step 3: Execute the userOp.
 */
describe('Execute userOp from Passkey signer [@userstory]', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { EntryPoint, Safe4337Module, SafeProxyFactory, SafeModuleSetup, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory } =
      await deployments.run()

    const [relayer] = await ethers.getSigners()

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

    // Deploy a signer contract
    const publicKey = decodePublicKey(credential.response)
    await signerFactory.createSigner(publicKey.x, publicKey.y, await verifier.getAddress())
    const signer = await signerFactory.getSigner(publicKey.x, publicKey.y, await verifier.getAddress())

    // Deploy a Safe with passkey signer as owner

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

    // Deploy a Safe with EOA and passkey signer as owners
    const safeSalt = Date.now()
    // Calculate the address of the Safe. Alternatively, address can be retrieved from the event logs or by calculating it off-chain via create2.
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton, setupData, safeSalt)
    await proxyFactory.createProxyWithNonce(singleton, setupData, safeSalt)

    return {
      relayer,
      module,
      entryPoint,
      navigator,
      signer,
      credential,
      safeAddress,
    }
  })

  it('should execute a userOp with WebAuthn signer as owner', async () => {
    const { relayer, module, entryPoint, navigator, signer, credential, safeAddress } = await setupTests()

    // Step 2: Create a userOp and sign it using passkey credential.
    const safeOp = buildSafeUserOpTransaction(
      safeAddress,
      ethers.ZeroAddress,
      ethers.parseEther('0.2'),
      '0x',
      await entryPoint.getNonce(safeAddress, 0),
      await entryPoint.getAddress(),
      false,
      true,
    )

    const packedUserOp = buildPackedUserOperationFromSafeUserOperation({
      safeOp: safeOp,
      signature: '0x',
    })

    const opHash = await module.getOperationHash(packedUserOp)

    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(opHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })

    // Build contract signature that the Safe will forward to the signer contract
    const signature2 = buildSignatureBytes([
      {
        signer: signer,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])

    packedUserOp.signature = ethers.solidityPacked(['uint48', 'uint48', 'bytes'], [safeOp.validAfter, safeOp.validUntil, signature2])

    // Step 3: Execute the userOp.

    // Send 1 ETH to the Safe for the transaction and the prefund
    await relayer.sendTransaction({ to: safeAddress, value: ethers.parseEther('1') })

    const balanceBefore = await ethers.provider.getBalance(ethers.ZeroAddress)

    await entryPoint.handleOps([packedUserOp], relayer.address)

    // Check if the address(0) received 0.2 ETH
    expect(await ethers.provider.getBalance(ethers.ZeroAddress)).to.be.equal(balanceBefore + ethers.parseEther('0.2'))
    expect(await ethers.provider.getBalance(safeAddress)).to.be.lessThanOrEqual(ethers.parseEther('1') - ethers.parseEther('0.2'))
  })
})
