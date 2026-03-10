import '@nomicfoundation/hardhat-toolbox'
import '@nomicfoundation/hardhat-ethers'
import dotenv from 'dotenv'
import type { HardhatUserConfig } from 'hardhat/config'
import 'hardhat-deploy'
import { HttpNetworkUserConfig } from 'hardhat/types'
import './src/tasks/codesize'
import './src/tasks/deployContracts'
import './src/tasks/localVerify'
import { getSingletonFactoryInfo } from '@safe-global/safe-singleton-factory'
import { DeterministicDeploymentInfo } from 'hardhat-deploy/dist/types'

dotenv.config()
const { CUSTOM_NODE_URL, MNEMONIC, ETHERSCAN_API_KEY, PK } = process.env

const DEFAULT_MNEMONIC = 'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'

const sharedNetworkConfig: HttpNetworkUserConfig = {}
if (PK) {
  sharedNetworkConfig.accounts = [PK]
} else {
  sharedNetworkConfig.accounts = {
    mnemonic: MNEMONIC || DEFAULT_MNEMONIC,
  }
}

const customNetwork = CUSTOM_NODE_URL
  ? {
      custom: {
        ...sharedNetworkConfig,
        url: CUSTOM_NODE_URL,
      },
    }
  : {}

const deterministicDeployment = (network: string): DeterministicDeploymentInfo => {
  const info = getSingletonFactoryInfo(parseInt(network))
  if (!info) {
    throw new Error(`
      Safe factory not found for network ${network}. You can request a new deployment at https://github.com/safe-global/safe-singleton-factory.
      For more information, see https://github.com/safe-global/safe-smart-account#replay-protection-eip-155
    `)
  }

  const gasLimit = BigInt(info.gasLimit)
  const gasPrice = BigInt(info.gasPrice)

  return {
    factory: info.address,
    deployer: info.signerAddress,
    funding: String(gasLimit * gasPrice),
    signedTx: info.transaction,
  }
}

const config: HardhatUserConfig = {
  paths: {
    artifacts: 'build/artifacts',
    cache: 'build/cache',
    deploy: 'src/deploy',
    sources: 'contracts',
  },
  networks: {
    localhost: {
      url: 'http://localhost:8545',
      tags: ['dev', 'entrypoint', 'safe'],
    },
    hardhat: {
      tags: ['test', 'entrypoint', 'safe'],
    },
    sepolia: {
      ...sharedNetworkConfig,
      url: 'https://rpc.ankr.com/eth_sepolia',
      tags: ['dev'],
    },
    ...customNetwork,
  },
  deterministicDeployment,
  solidity: {
    version: '0.8.26',
    settings: {
      optimizer: {
        enabled: true,
        runs: 10_000_000,
      },
      viaIR: true,
      evmVersion: 'paris',
    },
  },
  namedAccounts: {
    deployer: 0,
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
  sourcify: {
    enabled: true,
  },
}

export default config
