import { DeployFunction } from 'hardhat-deploy/types'
import { HardhatRuntimeEnvironment } from 'hardhat/types'

// MIN_DELAY and MAX_DELAY can be overridden via environment variables for testnet deploys.
// Defaults: 5 minutes minimum, 30 days maximum.
const MIN_DELAY = process.env.TIMELOCK_MIN_DELAY ? parseInt(process.env.TIMELOCK_MIN_DELAY) : 300
const MAX_DELAY = process.env.TIMELOCK_MAX_DELAY ? parseInt(process.env.TIMELOCK_MAX_DELAY) : 30 * 24 * 60 * 60

const deploy: DeployFunction = async (hre: HardhatRuntimeEnvironment) => {
  const { deployments, getNamedAccounts } = hre
  const { deploy } = deployments
  const { deployer } = await getNamedAccounts()

  await deploy('TimelockGuard', {
    from: deployer,
    args: [MIN_DELAY, MAX_DELAY],
    log: true,
    deterministicDeployment: true,
  })
}

deploy.tags = ['TimelockGuard']
export default deploy
