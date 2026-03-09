import { bundlerRpc, prepareAccounts, waitForUserOp } from '@safe-global/safe-4337-local-bundler'
import { expect } from 'chai'
import { deployments, ethers, network } from 'hardhat'
import { encodeMultiSendTransactions } from '@safe-global/safe-4337/test/utils/encoding'
import {
  buildSafeUserOpTransaction,
  buildPackedUserOperationFromSafeUserOperation,
  buildRpcUserOperationFromSafeUserOperation,
} from '@safe-global/safe-4337/src/utils/userOp'
import { buildSignatureBytes } from '@safe-global/safe-4337/src/utils/execution'
import { WebAuthnCredentials } from '../../utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../../src/utils/webauthn'

const SENTINEL = ethers.getAddress('0x0000000000000000000000000000000000000001')

describe('Safe WebAuthn Shared Signer [@4337]', () => {
  before(function () {
    if (network.name !== 'localhost') {
      this.skip()
    }
  })

  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const {
      EntryPoint,
      Safe4337Module,
      SafeProxyFactory,
      SafeModuleSetup,
      MultiSend,
      SafeL2,
      DaimoP256Verifier,
      SafeWebAuthnSharedSigner,
      SafeWebAuthnSignerFactory,
    } = await deployments.run()
    const [user] = await prepareAccounts()
    const bundler = bundlerRpc()

    const entryPoint = await ethers.getContractAt('IEntryPoint', EntryPoint.address)
    const module = await ethers.getContractAt(Safe4337Module.abi, Safe4337Module.address)
    const proxyFactory = await ethers.getContractAt(SafeProxyFactory.abi, SafeProxyFactory.address)
    const safeModuleSetup = await ethers.getContractAt(SafeModuleSetup.abi, SafeModuleSetup.address)
    const multiSend = await ethers.getContractAt(MultiSend.abi, MultiSend.address)
    const singleton = await ethers.getContractAt(SafeL2.abi, SafeL2.address)
    const verifier = await ethers.getContractAt('IP256Verifier', DaimoP256Verifier.address)
    const sharedSigner = await ethers.getContractAt('SafeWebAuthnSharedSigner', SafeWebAuthnSharedSigner.address)
    const signerFactory = await ethers.getContractAt('SafeWebAuthnSignerFactory', SafeWebAuthnSignerFactory.address)

    const navigator = {
      credentials: new WebAuthnCredentials(),
    }

    return {
      user,
      bundler,
      proxyFactory,
      safeModuleSetup,
      module,
      entryPoint,
      multiSend,
      singleton,
      verifier,
      sharedSigner,
      signerFactory,
      navigator,
    }
  })

  it('should execute a user op with the WebAuthn shared signer', async () => {
    const { user, bundler, proxyFactory, safeModuleSetup, module, entryPoint, multiSend, singleton, verifier, sharedSigner, navigator } =
      await setupTests()
    const verifierAddress = await verifier.getAddress()

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

    const initializer = singleton.interface.encodeFunctionData('setup', [
      [sharedSigner.target],
      1,
      multiSend.target,
      multiSend.interface.encodeFunctionData('multiSend', [
        encodeMultiSendTransactions([
          {
            op: 1 as const,
            to: safeModuleSetup.target,
            data: safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
          },
          {
            op: 1 as const,
            to: sharedSigner.target,
            data: sharedSigner.interface.encodeFunctionData('configure', [{ ...publicKey, verifiers: verifierAddress }]),
          },
        ]),
      ]),
      module.target,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const safeSalt = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton.target, initializer, safeSalt)
    const deployData = proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [singleton.target, initializer, safeSalt])
    const initCode = ethers.solidityPacked(['address', 'bytes'], [proxyFactory.target, deployData])

    const safeOp = buildSafeUserOpTransaction(
      safeAddress,
      user.address,
      ethers.parseEther('0.1'),
      '0x',
      await entryPoint.getNonce(safeAddress, 0),
      await entryPoint.getAddress(),
      false,
      false,
      {
        initCode,
        verificationGasLimit: 900000,
      },
    )
    const opHash = await module.getOperationHash(
      buildPackedUserOperationFromSafeUserOperation({
        safeOp,
        signature: '0x',
      }),
    )
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(opHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })
    const signature = buildSignatureBytes([
      {
        signer: sharedSigner.target as string,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])
    const userOp = await buildRpcUserOperationFromSafeUserOperation({
      safeOp,
      signature,
    })

    await user.sendTransaction({ to: safeAddress, value: ethers.parseEther('0.5') }).then((tx) => tx.wait())

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.equal(0)
    expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([0n, 0n, 0n])

    await bundler.sendUserOperation(userOp, await entryPoint.getAddress())
    await waitForUserOp(userOp)

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.not.equal(0)
    expect(await ethers.provider.getBalance(safeAddress)).to.be.lessThan(ethers.parseEther('0.4'))
    expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([publicKey.x, publicKey.y, verifier.target])
  })

  it('should execute a user op and deploy a new WebAuthn signer', async () => {
    const {
      user,
      bundler,
      proxyFactory,
      safeModuleSetup,
      module,
      entryPoint,
      multiSend,
      singleton,
      verifier,
      sharedSigner,
      signerFactory,
      navigator,
    } = await setupTests()
    const verifierAddress = await verifier.getAddress()

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
    const signerAddress = await signerFactory.getSigner(publicKey.x, publicKey.y, verifierAddress)

    const initializer = singleton.interface.encodeFunctionData('setup', [
      [sharedSigner.target],
      1,
      multiSend.target,
      multiSend.interface.encodeFunctionData('multiSend', [
        encodeMultiSendTransactions([
          {
            op: 1 as const,
            to: safeModuleSetup.target,
            data: safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
          },
          {
            op: 1 as const,
            to: sharedSigner.target,
            data: sharedSigner.interface.encodeFunctionData('configure', [{ ...publicKey, verifiers: verifierAddress }]),
          },
        ]),
      ]),
      module.target,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const safeSalt = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton.target, initializer, safeSalt)
    const deployData = proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [singleton.target, initializer, safeSalt])
    const initCode = ethers.solidityPacked(['address', 'bytes'], [proxyFactory.target, deployData])

    const safeOp = buildSafeUserOpTransaction(
      safeAddress,
      await multiSend.getAddress(),
      0,
      multiSend.interface.encodeFunctionData('multiSend', [
        encodeMultiSendTransactions([
          {
            op: 0 as const,
            to: signerFactory.target,
            data: signerFactory.interface.encodeFunctionData('createSigner', [publicKey.x, publicKey.y, verifierAddress]),
          },
          {
            op: 0 as const,
            to: safeAddress,
            data: singleton.interface.encodeFunctionData('swapOwner', [SENTINEL, sharedSigner.target, signerAddress]),
          },
          {
            op: 1 as const,
            to: sharedSigner.target,
            data: sharedSigner.interface.encodeFunctionData('configure', [{ x: 0, y: 0, verifiers: 0 }]),
          },
          {
            op: 0 as const,
            to: user.address,
            value: ethers.parseEther('0.1'),
            data: '0x',
          },
        ]),
      ]),
      await entryPoint.getNonce(safeAddress, 0),
      await entryPoint.getAddress(),
      true,
      false,
      {
        initCode,
        verificationGasLimit: 900000,
      },
    )
    const opHash = await module.getOperationHash(
      buildPackedUserOperationFromSafeUserOperation({
        safeOp,
        signature: '0x',
      }),
    )
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(opHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })
    const signature = buildSignatureBytes([
      {
        signer: sharedSigner.target as string,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])
    const userOp = await buildRpcUserOperationFromSafeUserOperation({
      safeOp,
      signature,
    })

    await user.sendTransaction({ to: safeAddress, value: ethers.parseEther('0.5') }).then((tx) => tx.wait())

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.equal(0)
    expect(ethers.dataLength(await ethers.provider.getCode(signerAddress))).to.equal(0)
    expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([0n, 0n, 0n])

    await bundler.sendUserOperation(userOp, await entryPoint.getAddress())
    await waitForUserOp(userOp)

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.not.equal(0)
    expect(ethers.dataLength(await ethers.provider.getCode(signerAddress))).to.not.equal(0)
    expect(await ethers.provider.getBalance(safeAddress)).to.be.lessThan(ethers.parseEther('0.4'))
    expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([0n, 0n, 0n])

    const safeInstance = singleton.attach(safeAddress) as typeof singleton
    expect(await safeInstance.getOwners()).to.deep.equal([signerAddress])
  })

  it('should execute a user op with multiple passkey owners', async () => {
    const {
      user,
      proxyFactory,
      safeModuleSetup,
      module,
      entryPoint,
      multiSend,
      singleton,
      verifier,
      sharedSigner: singletonSharedSigner,
      navigator,
    } = await setupTests()
    const verifierAddress = await verifier.getAddress()

    const credentials = [
      navigator.credentials.create({
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
      }),
      navigator.credentials.create({
        publicKey: {
          rp: {
            name: 'Safe',
            id: 'safe.global',
          },
          user: {
            id: ethers.getBytes(ethers.id('kratos')),
            name: 'kratos',
            displayName: 'Kratos of Sparta',
          },
          challenge: ethers.toBeArray(Date.now()),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
        },
      }),
    ]
    const publicKeys = credentials.map((credential) => decodePublicKey(credential.response))

    const SafeWebAuthnSharedSigner = await ethers.getContractFactory('SafeWebAuthnSharedSigner')
    const sharedSigners = [
      singletonSharedSigner,
      ...(await Promise.all([...Array(credentials.length - 1)].map(() => SafeWebAuthnSharedSigner.deploy()))),
    ]

    const initializer = singleton.interface.encodeFunctionData('setup', [
      sharedSigners.map((sharedSigner) => sharedSigner.target),
      sharedSigners.length,
      multiSend.target,
      multiSend.interface.encodeFunctionData('multiSend', [
        encodeMultiSendTransactions([
          {
            op: 1 as const,
            to: safeModuleSetup.target,
            data: safeModuleSetup.interface.encodeFunctionData('enableModules', [[module.target]]),
          },
          ...sharedSigners.map((sharedSigner, i) => ({
            op: 1 as const,
            to: sharedSigner.target,
            data: sharedSigner.interface.encodeFunctionData('configure', [{ ...publicKeys[i], verifiers: verifierAddress }]),
          })),
        ]),
      ]),
      module.target,
      ethers.ZeroAddress,
      0,
      ethers.ZeroAddress,
    ])
    const safeSalt = Date.now()
    const safeAddress = await proxyFactory.createProxyWithNonce.staticCall(singleton.target, initializer, safeSalt)
    const deployData = proxyFactory.interface.encodeFunctionData('createProxyWithNonce', [singleton.target, initializer, safeSalt])
    const initCode = ethers.solidityPacked(['address', 'bytes'], [proxyFactory.target, deployData])

    const safeOp = buildSafeUserOpTransaction(
      safeAddress,
      user.address,
      ethers.parseEther('0.1'),
      '0x',
      await entryPoint.getNonce(safeAddress, 0),
      await entryPoint.getAddress(),
      false,
      false,
      {
        initCode,
        verificationGasLimit: 1500000,
      },
    )
    const opHash = await module.getOperationHash(
      buildPackedUserOperationFromSafeUserOperation({
        safeOp,
        signature: '0x',
      }),
    )
    const assertions = credentials.map((credential) =>
      navigator.credentials.get({
        publicKey: {
          challenge: ethers.getBytes(opHash),
          rpId: 'safe.global',
          allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
          userVerification: 'required',
        },
      }),
    )
    const signature = buildSignatureBytes(
      assertions.map((assertion, i) => ({
        signer: sharedSigners[i].target as string,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      })),
    )
    const packedUserOp = buildPackedUserOperationFromSafeUserOperation({ safeOp, signature })
    const userOp = await buildRpcUserOperationFromSafeUserOperation({ safeOp, signature })

    await user.sendTransaction({ to: safeAddress, value: ethers.parseEther('0.5') }).then((tx) => tx.wait())

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.equal(0)
    for (const sharedSigner of sharedSigners) {
      expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([0n, 0n, 0n])
    }

    // We cannot send this directly to the bundler because the tracing logic times out :/. For now,
    // just execute the user operation directly as the relayer to show that the signature
    // verification with two signers works.
    //await bundler.sendUserOperation(userOp, await entryPoint.getAddress())
    await entryPoint.handleOps([packedUserOp], user.address)
    await waitForUserOp(userOp)

    expect(ethers.dataLength(await ethers.provider.getCode(safeAddress))).to.not.equal(0)
    expect(await ethers.provider.getBalance(safeAddress)).to.be.lessThan(ethers.parseEther('0.4'))
    for (const [sharedSigner, publicKey] of sharedSigners.map((sharedSigner, i) => [sharedSigner, publicKeys[i]] as const)) {
      expect(await sharedSigner.getConfiguration(safeAddress)).to.deep.equal([publicKey.x, publicKey.y, verifier.target])
    }
  })
})
