import { config } from 'dotenv'
import { ethers } from 'ethers'

config()

const key = process.env.PRIVATE_KEY
if (key === undefined || key === '') {
  console.error('PRIVATE_KEY not loaded — check .env path and format')
  process.exit(1)
}

const wallet = new ethers.Wallet(key)
console.log('Deployer address:', wallet.address)

const provider = new ethers.JsonRpcProvider(process.env.CUSTOM_NODE_URL)
const network = await provider.getNetwork()
console.log('Chain ID:', network.chainId.toString(), '(Sepolia = 11155111)')
const balance = await provider.getBalance(wallet.address)
console.log('Balance:', ethers.formatEther(balance), 'ETH')
