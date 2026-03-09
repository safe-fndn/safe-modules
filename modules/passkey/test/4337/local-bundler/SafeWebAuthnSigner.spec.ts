import { expect } from 'chai'
import { deployments, ethers, network } from 'hardhat'
import { Safe4337 } from '@safe-global/safe-4337/src/utils/safe'
import {
  buildRpcUserOperationFromSafeUserOperation,
  buildSafeUserOpTransaction,
  calculateSafeOperationHash,
} from '@safe-global/safe-4337/src/utils/userOp'
import { bundlerRpc, prepareAccounts, waitForUserOp } from '@safe-global/safe-4337-local-bundler'
import { WebAuthnCredentials } from '../../utils/webauthnShim'
import { decodePublicKey, encodeWebAuthnSignature } from '../../../src/utils/webauthn'
import { buildSignatureBytes } from '@safe-global/safe-4337/src/utils/execution'

describe('Safe WebAuthn Signer [@4337]', () => {
  before(function () {
    if (network.name !== 'localhost') {
      this.skip()
    }
  })

  const setupTests = deployments.createFixture(async ({ deployments }) => {
    const { EntryPoint, Safe4337Module, SafeProxyFactory, SafeModuleSetup, SafeL2, DaimoP256Verifier, SafeWebAuthnSignerFactory } =
      await deployments.run()
    const [user] = await prepareAccounts()
    const bundler = bundlerRpc()

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

    return {
      user,
      bundler,
      proxyFactory,
      safeModuleSetup,
      module,
      entryPoint,
      singleton,
      signerFactory,
      navigator,
      verifier,
    }
  })

  it('should execute a user op with a deployed WebAuthn signer', async () => {
    const { user, bundler, proxyFactory, safeModuleSetup, module, entryPoint, singleton, signerFactory, navigator, verifier } =
      await setupTests()

    const { chainId } = await ethers.provider.getNetwork()
    const verifiers = ethers.solidityPacked(['uint16', 'address'], [0, await verifier.getAddress()])

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
    const signerAddress = await signerFactory.getSigner(publicKey.x, publicKey.y, verifiers)
    await signerFactory.createSigner(publicKey.x, publicKey.y, verifiers).then((tx) => tx.wait())

    const safe = await Safe4337.withSigner(signerAddress, {
      safeSingleton: await singleton.getAddress(),
      entryPoint: await entryPoint.getAddress(),
      erc4337module: await module.getAddress(),
      proxyFactory: await proxyFactory.getAddress(),
      safeModuleSetup: await safeModuleSetup.getAddress(),
      proxyCreationCode: await proxyFactory.proxyCreationCode(),
      chainId: Number(chainId),
    })

    const safeOp = buildSafeUserOpTransaction(
      safe.address,
      user.address,
      ethers.parseEther('0.5'),
      '0x',
      '0',
      await entryPoint.getAddress(),
      false,
      false,
      {
        initCode: safe.getInitCode(),
        verificationGasLimit: 800000,
      },
    )
    const safeOpHash = calculateSafeOperationHash(await module.getAddress(), safeOp, chainId)
    const assertion = navigator.credentials.get({
      publicKey: {
        challenge: ethers.getBytes(safeOpHash),
        rpId: 'safe.global',
        allowCredentials: [{ type: 'public-key', id: new Uint8Array(credential.rawId) }],
        userVerification: 'required',
      },
    })
    const signature = buildSignatureBytes([
      {
        signer: signerAddress,
        data: encodeWebAuthnSignature(assertion.response),
        dynamic: true,
      },
    ])

    await user.sendTransaction({ to: safe.address, value: ethers.parseEther('1') }).then((tx) => tx.wait())
    expect(await ethers.provider.getCode(safe.address)).to.equal('0x')
    expect(await ethers.provider.getBalance(safe.address)).to.equal(ethers.parseEther('1'))

    const userOp = await buildRpcUserOperationFromSafeUserOperation({ safeOp, signature })
    await bundler.sendUserOperation(userOp, await entryPoint.getAddress())
    await waitForUserOp(userOp)

    expect(await ethers.provider.getBalance(safe.address)).to.be.lessThanOrEqual(ethers.parseEther('0.5'))
    expect(await ethers.provider.getCode(safe.address)).to.not.equal('0x')
    expect(await ethers.provider.getCode(signerAddress)).to.not.equal('0x')

    const safeInstance = new ethers.Contract(safe.address, singleton.interface, ethers.provider)
    expect(await safeInstance.getOwners()).to.deep.equal([signerAddress])
  })
})
