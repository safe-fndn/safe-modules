import { buildSignatureBytes } from '@safe-global/safe-4337/dist/src/utils/execution'
import { expect } from 'chai'
import { deployments, ethers } from 'hardhat'
import { WebAuthnCredentials } from '../../test/utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../src/utils/webauthn'

/**
 * User story: Execute Safe Transaction
 * This user story how to use a passkey owner for a Safe and sign and execute a transaction with it.
 */
describe('Execute Safe Transaction [@userstory]', () => {
  const navigator = {
    // Setup a WebAuthn shim for tests.
    credentials: new WebAuthnCredentials(),
  }

  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { SafeProxyFactory, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory, SafeWebAuthnSharedSigner } = await deployments.run()

    const [relayer] = await ethers.getSigners()

    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)
    const sharedSigner = await ethers.getContractAt('SafeWebAuthnSharedSigner', SafeWebAuthnSharedSigner.address)

    return {
      relayer,
      proxyFactory,
      singleton,
      signerFactory,
      sharedSigner,
      navigator,
      verifier,
      SafeL2,
    }
  })

  it('should create a Safe and execute a transaction', async () => {
    const { relayer, singleton, proxyFactory, verifier, navigator, SafeL2, signerFactory } = await setupTests()

    // Create a WebAuthn credential to own the Safe.
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

    // Deploy a signer for the created credential. Note that this uses a deterministic address,
    // meaning that deployment of the signer can be delayed until when it is needed for verifying
    // signatures (i.e. you can MultiSend the deployment of the signer with the first call to
    // `Safe.execTransaction`).
    const publicKey = decodePublicKey(credential.response)
    await signerFactory.createSigner(publicKey.x, publicKey.y, await verifier.getAddress())
    const signerAddress = await signerFactory.getSigner(publicKey.x, publicKey.y, await verifier.getAddress())

    // Deploy a Safe that is owned by the WebAuthn credential signer. Note that it is **not
    // recommended** to deploy a Safe that is owned only by a WebAuthn credential without a recovery
    // mechanism.
    const setupData = singleton.interface.encodeFunctionData('setup', [
      [signerAddress],
      1n,
      ethers.ZeroAddress,
      '0x',
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const saltNonce = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton, setupData, saltNonce)
    await proxyFactory.createProxyWithNonce(singleton, setupData, saltNonce)
    const safe = await ethers.getContractAt(SafeL2.abi, safeAddress)

    // Prepare a Safe transaction and compute its hash.
    const transaction = {
      to: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
      value: 0n,
      data: '0x',
      operation: 0,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ethers.ZeroAddress,
      refundReceiver: ethers.ZeroAddress,
      nonce: await safe.nonce(),
    }
    const { chainId } = await ethers.provider.getNetwork()
    const transactionHash = ethers.TypedDataEncoder.hash(
      {
        chainId,
        verifyingContract: await safe.getAddress(),
      },
      {
        SafeTx: [
          { type: 'address', name: 'to' },
          { type: 'uint256', name: 'value' },
          { type: 'bytes', name: 'data' },
          { type: 'uint8', name: 'operation' },
          { type: 'uint256', name: 'safeTxGas' },
          { type: 'uint256', name: 'baseGas' },
          { type: 'uint256', name: 'gasPrice' },
          { type: 'address', name: 'gasToken' },
          { type: 'address', name: 'refundReceiver' },
          { type: 'uint256', name: 'nonce' },
        ],
      },
      transaction,
    )

    // Sign the transaction hash with the WebAuthn credential.
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(transactionHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })
    const signatureData = encodeWebAuthnSignature(assertion.response)

    // Use relayer account to execute the signed Safe transaction.
    const relayedSafe = safe.connect(relayer) as typeof safe
    expect(
      await relayedSafe.execTransaction(
        transaction.to,
        transaction.value,
        transaction.data,
        transaction.operation,
        transaction.safeTxGas,
        transaction.baseGas,
        transaction.gasPrice,
        transaction.gasToken,
        transaction.refundReceiver,
        buildSignatureBytes([
          {
            signer: signerAddress,
            data: signatureData,
            dynamic: true,
          },
        ]),
      ),
    ).to.not.be.reverted
  })

  it('should create a Safe and execute a transaction with the shared WebAuthn signer', async () => {
    const { relayer, singleton, proxyFactory, verifier, navigator, SafeL2, sharedSigner } = await setupTests()

    // Create a WebAuthn credential to own the Safe.
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

    // Deploy a Safe that is owned by the WebAuthn shared signer. Note that it is **not
    // recommended** to deploy a Safe that is owned only by a WebAuthn credential without a recovery
    // mechanism.
    const setupData = singleton.interface.encodeFunctionData('setup', [
      [await sharedSigner.getAddress()],
      1n,
      // The WebAuthn shared signer is a singleton contract that can be shared across Safes. This
      // reduces the deployment cost (as there is no contract creation for the signer representing
      // the WebAuthn credential on-chain), but has some additional limitations:
      // 1. You can only have one WebAuthn owner per Safe this way (additional WebAuthn owners need
      //    to be added by creating a SafeWebAuthnSignerProxy as demonstrated above).
      // 2. Signature verification is slightly more gas intensive (as the WebAuthn credential is
      //    read from storage).
      //
      // We use the Safe's setup mechanism to configure the WebAuthn credentials with the shared
      // signer.
      await sharedSigner.getAddress(),
      sharedSigner.interface.encodeFunctionData('configure', [
        {
          ...decodePublicKey(credential.response),
          verifiers: await verifier.getAddress(),
        },
      ]),
      ethers.ZeroAddress,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const saltNonce = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton, setupData, saltNonce)
    await proxyFactory.createProxyWithNonce(singleton, setupData, saltNonce)
    const safe = await ethers.getContractAt(SafeL2.abi, safeAddress)

    // Prepare a Safe transaction and compute its hash.
    const transaction = {
      to: '0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE',
      value: 0n,
      data: '0x',
      operation: 0,
      safeTxGas: 0n,
      baseGas: 0n,
      gasPrice: 0n,
      gasToken: ethers.ZeroAddress,
      refundReceiver: ethers.ZeroAddress,
      nonce: await safe.nonce(),
    }
    const { chainId } = await ethers.provider.getNetwork()
    const transactionHash = ethers.TypedDataEncoder.hash(
      {
        chainId,
        verifyingContract: await safe.getAddress(),
      },
      {
        SafeTx: [
          { type: 'address', name: 'to' },
          { type: 'uint256', name: 'value' },
          { type: 'bytes', name: 'data' },
          { type: 'uint8', name: 'operation' },
          { type: 'uint256', name: 'safeTxGas' },
          { type: 'uint256', name: 'baseGas' },
          { type: 'uint256', name: 'gasPrice' },
          { type: 'address', name: 'gasToken' },
          { type: 'address', name: 'refundReceiver' },
          { type: 'uint256', name: 'nonce' },
        ],
      },
      transaction,
    )

    // Sign the transaction hash with the WebAuthn credential.
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(transactionHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })
    const signatureData = encodeWebAuthnSignature(assertion.response)

    // Use relayer account to execute the signed Safe transaction.
    const relayedSafe = safe.connect(relayer) as typeof safe
    expect(
      await relayedSafe.execTransaction(
        transaction.to,
        transaction.value,
        transaction.data,
        transaction.operation,
        transaction.safeTxGas,
        transaction.baseGas,
        transaction.gasPrice,
        transaction.gasToken,
        transaction.refundReceiver,
        buildSignatureBytes([
          {
            signer: await sharedSigner.getAddress(),
            data: signatureData,
            dynamic: true,
          },
        ]),
      ),
    ).to.not.be.reverted
  })
})
