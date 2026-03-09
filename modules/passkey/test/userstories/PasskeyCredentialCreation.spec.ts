import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../src/utils/webauthn'
import { buildSignatureBytes } from '@safe-global/safe-4337/src/utils/execution'
import { buildSafeTransaction, buildSafeTransactionData, SafeDomain } from '../utils/safe'

/**
 * User story: Passkey Credential Creation for Safe Ownership
 * The user story here creates a passkey signer, deploys a Safe with that signer and executes a transaction.
 *
 * The flow can be summarized as follows:
 * Step 1: Setup the contracts.
 * Step 2: Create the `SafeMessage` from the intended transaction, hash it and finally create the signature for the hash by the passkey signer.
 * Step 3: Execute the transaction.
 */
describe('Passkey Credential Creation for Safe Ownership [@userstory]', () => {
  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { SafeProxyFactory, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory, CompatibilityFallbackHandler } = await deployments.run()
    const [user] = await ethers.getSigners()

    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const fallbackHandler = await ethers.getContractAt(CompatibilityFallbackHandler.abi, CompatibilityFallbackHandler.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)
    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)
    const verifierAddress = await verifier.getAddress()

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    // Create the credentials for Passkey.
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

    // Get the publicKey from the credential and create the signer.
    const publicKey = decodePublicKey(credential.response)
    await signerFactory.createSigner(publicKey.x, publicKey.y, verifierAddress)
    const signerAddress = await signerFactory.getSigner(publicKey.x, publicKey.y, verifierAddress)
    const signer = await ethers.getContractAt('SafeWebAuthnSignerSingleton', signerAddress)

    // Deploy Safe with the WebAuthn signer as a single owner.
    const singletonAddress = await singleton.getAddress()
    const setupData = singleton.interface.encodeFunctionData('setup', [
      [signerAddress],
      1,
      ethers.ZeroAddress,
      '0x',
      await fallbackHandler.getAddress(),
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singletonAddress, setupData, 0)
    await proxyFactory.createProxyWithNonce(singletonAddress, setupData, 0)
    const safe = await ethers.getContractAt([...SafeL2.abi, ...CompatibilityFallbackHandler.abi], safeAddress)

    const { chainId } = await ethers.provider.getNetwork()
    const safeDomain: SafeDomain = { verifyingContract: safeAddress, chainId: chainId }

    return {
      user,
      safe,
      safeAddress,
      safeDomain,
      signer,
      navigator,
      credential,
    }
  })

  it('should be possible to execute a transaction signed by passkey', async () => {
    const { user, safe, safeAddress, safeDomain, signer, navigator, credential } = await setupTests()

    // Send 1 wei to the Safe
    await user.sendTransaction({ to: safe, value: 1n })

    // Define transaction to be signed.
    const nonce = await safe.nonce()
    const randomAddress = ethers.getAddress(ethers.hexlify(ethers.randomBytes(20)))
    const safeTx = buildSafeTransaction({ to: randomAddress, value: 1n, nonce: nonce })
    const safeTxData = buildSafeTransactionData(safeDomain, safeTx)
    const message = ethers.keccak256(safeTxData) // Safe Tx Hash

    // Creating the signature for the `safeMsgHash`.
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(message),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })

    // Encode the passkey signature for the safe.
    const signature = buildSignatureBytes([
      {
        signer: await signer.getAddress(),
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])

    const receiverBeforeBalance = await ethers.provider.getBalance(randomAddress)
    const safeBeforeBalance = await ethers.provider.getBalance(safeAddress)

    // Execute Transaction.
    await safe.execTransaction(
      safeTx.to,
      safeTx.value,
      safeTx.data,
      safeTx.operation,
      safeTx.safeTxGas,
      safeTx.baseGas,
      safeTx.gasPrice,
      safeTx.gasToken,
      safeTx.refundReceiver,
      signature,
    )

    const receiverAfterBalance = await ethers.provider.getBalance(randomAddress)
    const safeAfterBalance = await ethers.provider.getBalance(safeAddress)

    expect(receiverAfterBalance).to.eq(receiverBeforeBalance + safeTx.value)
    expect(safeAfterBalance).to.eq(safeBeforeBalance - safeTx.value)
  })
})
