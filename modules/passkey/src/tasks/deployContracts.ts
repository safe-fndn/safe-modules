import { task } from 'hardhat/config'

task('deploy-contracts', 'Deploys and verifies Safe contracts').setAction(async (_, { deployments, run }) => {
  await run('deploy')
  await run('local-verify')
  await run('etherscan-verify', { forceLicense: true, license: 'LGPL-3.0-only' })
  await run('sourcify')

  // The `SafeWebAuthnSignerSingleton` is deployed by the `SafeWebAuthnSignerFactory` contructor
  // and not by the deployment script, so it does not automatically get verified. We work around
  // this by manually using the `hardhat-verify` plugin to verify the contract on Etherscan.
  const signerSingleton = await deployments.read('SafeWebAuthnSignerFactory', 'SINGLETON')
  await run('verify', { address: signerSingleton, contract: 'contracts/SafeWebAuthnSignerSingleton.sol:SafeWebAuthnSignerSingleton' })
})

export {}
