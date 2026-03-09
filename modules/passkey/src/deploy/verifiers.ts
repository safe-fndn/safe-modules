import type { HardhatRuntimeEnvironment } from 'hardhat/types'
import type { DeployFunction } from 'hardhat-deploy/types'

import DaimoP256Verifier from '../vendor/daimo-eth/P256Verifier.json'

const deploy: DeployFunction = async (hre) => {
  const { deployments, getNamedAccounts } = hre

  const { deployer } = await getNamedAccounts()
  const { deploy } = deployments

  // The official Daimo P-256 verifier contract is deployed using the Arachnid CREATE2 deployer.
  await withArachnidDeterministicDeploymentProxy(hre, () =>
    deploy('DaimoP256Verifier', {
      from: deployer,
      contract: DaimoP256Verifier,
      args: [],
      deterministicDeployment: true,
      log: true,
    }),
  )
}

function withArachnidDeterministicDeploymentProxy<T>({ config }: HardhatRuntimeEnvironment, f: () => Promise<T>): Promise<T> {
  // This is a bit hacky - but the `hardhat-deploy` package reads that deterministic deployment
  // configuration before deploying each contract. This means that we can temporarily override the
  // the configuration to `undefined` so that it uses the (default) Arachnid deterministic
  // deployment proxy for a specific deployment, and then restore the configuration afterwards so
  // that remaining contracts use the deterministic deployment factory from `hardhat.config.ts`.
  const existingConfig = config.deterministicDeployment
  config.deterministicDeployment = undefined
  return f().finally(() => {
    config.deterministicDeployment = existingConfig
  })
}

export default deploy
