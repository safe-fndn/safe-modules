import { HardhatRuntimeEnvironment } from 'hardhat/types'
import { DeployFunction } from 'hardhat-deploy/types'

const deploy: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments } = hre
  const { deploy } = deployments
  const { deployer } = await hre.getNamedAccounts()

  await deploy('TestToken', {
    from: deployer,
    args: [],
    log: true,
    deterministicDeployment: true,
  })
}

deploy.tags = ['TestToken']

export default deploy
