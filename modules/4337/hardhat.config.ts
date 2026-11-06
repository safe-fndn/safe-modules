import '@nomicfoundation/hardhat-toolbox'
import '@nomicfoundation/hardhat-ethers'
import 'hardhat-deploy'
import dotenv from 'dotenv'
import type { HardhatUserConfig, HttpNetworkUserConfig } from 'hardhat/types'
import yargs from 'yargs'
import { getSingletonFactoryInfo } from '@safe-global/safe-singleton-factory'
import { DeterministicDeploymentInfo } from 'hardhat-deploy/dist/types'
import './src/tasks/localVerify'
import './src/tasks/deployContracts'
import './src/tasks/codesize'

const argv = yargs(process.argv.slice(2))
  .options({ network: { type: 'string', default: 'hardhat' } })
  .help(false)
  .version(false)
  .parseSync()

// Load environment variables.
dotenv.config()
const { NODE_URL, INFURA_KEY, MNEMONIC, ETHERSCAN_API_KEY, PK, SOLIDITY_VERSION, SOLIDITY_SETTINGS } = process.env

const DEFAULT_MNEMONIC = 'candy maple cake sugar pudding cream honey rich smooth crumble sweet treat'

const sharedNetworkConfig: HttpNetworkUserConfig = {}
if (PK) {
  sharedNetworkConfig.accounts = [PK]
} else {
  sharedNetworkConfig.accounts = {
    mnemonic: MNEMONIC || DEFAULT_MNEMONIC,
  }
}

if (['mainnet', 'sepolia', 'polygon', 'amoy'].includes(argv.network) && INFURA_KEY === undefined) {
  throw new Error(`Could not find Infura key in env, unable to connect to network ${argv.network}`)
}

const solidityVersion = SOLIDITY_VERSION || '0.8.23'
const soliditySettings = SOLIDITY_SETTINGS
  ? JSON.parse(SOLIDITY_SETTINGS)
  : {
      evmVersion: 'paris',
      optimizer: {
        enabled: true,
        runs: 10_000_000,
      },
    }

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

const customNetwork = NODE_URL
  ? {
      custom: {
        ...sharedNetworkConfig,
        url: NODE_URL,
      },
    }
  : {}

const userConfig: HardhatUserConfig = {
  paths: {
    artifacts: 'build/artifacts',
    cache: 'build/cache',
    deploy: 'src/deploy',
    sources: 'contracts',
  },
  solidity: {
    version: solidityVersion,
    settings: soliditySettings,
  },
  networks: {
    localhost: {
      url: 'http://localhost:8545',
      tags: ['dev', 'entrypoint', 'safe'],
    },
    hardhat: {
      gasPrice: 10000000000,
      tags: ['test', 'entrypoint', 'safe'],
    },
    mainnet: {
      ...sharedNetworkConfig,
      url: `https://mainnet.infura.io/v3/${INFURA_KEY}`,
    },
    gnosis: {
      ...sharedNetworkConfig,
      url: 'https://rpc.gnosis.gateway.fm',
    },
    polygon: {
      ...sharedNetworkConfig,
      url: `https://polygon-mainnet.infura.io/v3/${INFURA_KEY}`,
    },
    sepolia: {
      ...sharedNetworkConfig,
      url: `https://sepolia.infura.io/v3/${INFURA_KEY}`,
      tags: ['dev', 'entrypoint'],
    },
    amoy: {
      ...sharedNetworkConfig,
      url: `https://polygon-amoy.infura.io/v3/${INFURA_KEY}`,
      tags: ['dev', 'entrypoint'],
    },
    ...customNetwork,
  },
  deterministicDeployment,
  namedAccounts: {
    deployer: 0,
  },
  mocha: {
    timeout: 2000000,
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
}
export default userConfig
