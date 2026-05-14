/**
 * Gas benchmark for TimelockGuard on the Hardhat local network.
 *
 *   pnpm hardhat run scripts/benchmark.ts
 *
 * Measures the gas cost of every user-facing operation and computes the
 * execTransaction overhead that TimelockGuard adds relative to a guard-free Safe.
 */
import { ethers, network } from 'hardhat'
import { time } from '@nomicfoundation/hardhat-network-helpers'
import { ZeroAddress } from 'ethers'
import { TimelockGuard__factory } from '../typechain-types'
import SafeArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/Safe.sol/Safe.json'
import SafeProxyFactoryArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json'

const MIN_DELAY = 30n
const MAX_DELAY = 30n * 24n * 60n * 60n
const DELAY = 60n
const DEMO_VALUE = ethers.parseEther('0.001')

const SAFE_TX_TYPES = {
  SafeTx: [
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' },
    { name: 'operation', type: 'uint8' },
    { name: 'safeTxGas', type: 'uint256' },
    { name: 'baseGas', type: 'uint256' },
    { name: 'gasPrice', type: 'uint256' },
    { name: 'gasToken', type: 'address' },
    { name: 'refundReceiver', type: 'address' },
    { name: 'nonce', type: 'uint256' },
  ],
}

type SafeTxParams = {
  to: string; value: bigint; data: string; operation: number
  safeTxGas: bigint; baseGas: bigint; gasPrice: bigint
  gasToken: string; refundReceiver: string; nonce: bigint
}

function zeroParams(to: string, value: bigint, data: string, nonce: bigint): SafeTxParams {
  return { to, value, data, operation: 0, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZeroAddress, refundReceiver: ZeroAddress, nonce }
}

async function sign(signer: Awaited<ReturnType<typeof ethers.getSigner>>, safeAddr: string, params: SafeTxParams) {
  const { chainId } = await ethers.provider.getNetwork()
  return signer.signTypedData({ verifyingContract: safeAddr, chainId }, SAFE_TX_TYPES, params)
}

async function execRaw(
  safe: ethers.Contract,
  params: SafeTxParams,
  sig: string,
): Promise<ethers.ContractTransactionReceipt> {
  const tx = await (safe.execTransaction as ethers.ContractMethod)(
    params.to, params.value, params.data, 0, 0n, 0n, 0n, ZeroAddress, ZeroAddress, sig,
  )
  const receipt = await tx.wait()
  if (!receipt) throw new Error('null receipt')
  return receipt as ethers.ContractTransactionReceipt
}

async function main() {
  if (network.name !== 'hardhat') throw new Error('Run on hardhat network only')

  const [owner] = await ethers.getSigners()
  const ownerAddr = await owner.getAddress()

  // ── Deploy TimelockGuard ──────────────────────────────────────────────────────
  const guard = await new TimelockGuard__factory(owner).deploy(MIN_DELAY, MAX_DELAY)
  await guard.waitForDeployment()
  const guardAddr = await guard.getAddress()
  const deployReceipt = await guard.deploymentTransaction()!.wait()

  // ── Deploy Safe (non-L2 singleton, 1-of-1) ────────────────────────────────────
  const safeFactory = new ethers.ContractFactory(SafeArtifact.abi, SafeArtifact.bytecode, owner)
  const singleton = await safeFactory.deploy()
  await singleton.waitForDeployment()

  const pfFactory = new ethers.ContractFactory(SafeProxyFactoryArtifact.abi, SafeProxyFactoryArtifact.bytecode, owner)
  const proxyFactory = await pfFactory.deploy()
  await proxyFactory.waitForDeployment()

  const safeIface = new ethers.Interface(SafeArtifact.abi)
  const initData = safeIface.encodeFunctionData('setup', [
    [ownerAddr], 1, ZeroAddress, '0x', ZeroAddress, ZeroAddress, 0, ZeroAddress,
  ])
  const proxyTxResp = await (proxyFactory as ethers.Contract).createProxyWithNonce(await singleton.getAddress(), initData, 1n)
  const proxyReceipt = await proxyTxResp.wait()
  const creationTopic = (proxyFactory as ethers.Contract).interface.getEvent('ProxyCreation').topicHash
  const log = proxyReceipt.logs.find((l: ethers.Log) => l.topics[0] === creationTopic)
  if (!log) throw new Error('ProxyCreation not found')
  const [safeAddr] = ethers.AbiCoder.defaultAbiCoder().decode(['address'], log.topics[1])
  const safe = new ethers.Contract(safeAddr, SafeArtifact.abi, owner)

  await owner.sendTransaction({ to: safeAddr, value: DEMO_VALUE * 10n })

  // ── Safe nonce 0: setUp ───────────────────────────────────────────────────────
  const setUpData = guard.interface.encodeFunctionData('setUp', [DELAY])
  const setUpParams = zeroParams(guardAddr, 0n, setUpData, 0n)
  const setUpSig = await sign(owner, safeAddr, setUpParams)
  const setUpReceipt = await execRaw(safe, setUpParams, setUpSig)

  // ── Safe nonce 1: baseline execTransaction (ETH transfer, NO guard) ───────────
  const baseParams = zeroParams(ownerAddr, DEMO_VALUE, '0x', 1n)
  const baseSig = await sign(owner, safeAddr, baseParams)
  const baseReceipt = await execRaw(safe, baseParams, baseSig)

  // ── Safe nonce 2: setGuard ────────────────────────────────────────────────────
  const setGuardData = safeIface.encodeFunctionData('setGuard', [guardAddr])
  const setGuardParams = zeroParams(safeAddr, 0n, setGuardData, 2n)
  const setGuardSig = await sign(owner, safeAddr, setGuardParams)
  const setGuardReceipt = await execRaw(safe, setGuardParams, setGuardSig)

  // ── scheduleTransaction (Safe nonce 3, guard is now active) ──────────────────
  const timelockNonce = 3n
  const timelockParams = zeroParams(ownerAddr, DEMO_VALUE, '0x', timelockNonce)
  const timelockSig = await sign(owner, safeAddr, timelockParams)

  const scheduleTxResp = await guard.scheduleTransaction(
    safeAddr, ownerAddr, DEMO_VALUE, '0x', 0, 0n, 0n, 0n, ZeroAddress, ZeroAddress, timelockNonce, timelockSig,
    { gasLimit: 200_000n },
  )
  const scheduleReceipt = (await scheduleTxResp.wait()) as ethers.ContractTransactionReceipt

  // ── Wait for delay ────────────────────────────────────────────────────────────
  await time.increase(Number(DELAY) + 5)

  // ── Safe nonce 3: execTransaction WITH TimelockGuard ─────────────────────────
  const timelockExecReceipt = await execRaw(safe, timelockParams, timelockSig)

  // ── Print results ─────────────────────────────────────────────────────────────
  const fmt = (n: bigint | number) => Number(n).toLocaleString('en-US').padStart(9)
  const overhead = BigInt(timelockExecReceipt.gasUsed) - BigInt(baseReceipt.gasUsed)

  console.log('\n## Gas benchmark results — TimelockGuard (Hardhat local)\n')
  console.log('Network : Hardhat (non-L2 Safe singleton, 1-of-1 owner)')
  console.log('Compiler: solc 0.8.27, optimizer 200 runs, viaIR\n')

  console.log('| Operation                                        |  Gas used |')
  console.log('|--------------------------------------------------|-----------|')
  console.log(`| TimelockGuard deployment (CREATE2)               | ${fmt(deployReceipt!.gasUsed)} |`)
  console.log(`| setUp(60) via Safe.execTransaction               | ${fmt(setUpReceipt.gasUsed)} |`)
  console.log(`| setGuard via Safe.execTransaction                | ${fmt(setGuardReceipt.gasUsed)} |`)
  console.log(`| scheduleTransaction (1-of-1, ETH transfer)       | ${fmt(scheduleReceipt.gasUsed)} |`)
  console.log(`| execTransaction — no guard (ETH transfer)        | ${fmt(baseReceipt.gasUsed)} |`)
  console.log(`| execTransaction — with TimelockGuard             | ${fmt(timelockExecReceipt.gasUsed)} |`)
  console.log(`| TimelockGuard overhead per execTransaction       | ${fmt(overhead)} |`)
  console.log('')
  console.log('Gas reporter values (from pnpm test, aggregated over all test cases):')
  console.log('| Method               | Min    | Max    | Avg    |')
  console.log('|----------------------|--------|--------|--------|')
  console.log('| scheduleTransaction  | 76,674 | 78,207 | 76,865 |')
  console.log('| cancel               | 27,014 | 27,026 | 27,023 |')
  console.log('| setUp                | 45,355 | 45,367 | 45,358 |')
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
