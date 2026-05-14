/**
 * Full TimelockGuard lifecycle demo on Sepolia.
 *
 *   pnpm hardhat run scripts/demo-sepolia.ts --network sepolia
 *
 * Steps executed:
 *   1. Deploy a fresh 1-of-1 Safe proxy
 *   2. Fund the Safe (0.0002 ETH)
 *   3. Safe calls TimelockGuard.setUp(60)          — no guard yet, executes immediately
 *   4. Safe calls Safe.setGuard(timelockGuard)     — installs the guard
 *   5. Anyone calls scheduleTransaction(...)       — records readyAt = now + 60s
 *   6. Wait for the delay to elapse
 *   7. Safe calls execTransaction(...)             — guard allows, ETH delivered
 *
 * After the script completes, copy the printed tx hashes into
 * timelock-guard-project/docs/sepolia-evidence.md.
 */
import { ethers } from 'hardhat'
import { getSafeL2SingletonDeployment, getProxyFactoryDeployment } from '@safe-global/safe-deployments'
import SafeArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/Safe.sol/Safe.json'
import SafeProxyFactoryArtifact from '@safe-global/safe-smart-account/build/artifacts/contracts/proxies/SafeProxyFactory.sol/SafeProxyFactory.json'
import { TimelockGuard__factory } from '../typechain-types'

// ── Configuration ─────────────────────────────────────────────────────────────

const GUARD_ADDRESS = '0x27c5Bd9DCA0fF2Af1a493faF93923c3378598462'
const SETUP_DELAY = 60n // seconds — must be >= guard's MIN_DELAY (30)
const DEMO_VALUE = ethers.parseEther('0.0001') // ETH sent in the test tx
const ZERO = ethers.ZeroAddress

// EIP-712 types for Safe transaction signing
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

// ── Helpers ───────────────────────────────────────────────────────────────────

function explorerTx(hash: string): string {
  return `https://sepolia.etherscan.io/tx/${hash}`
}

function explorerAddr(addr: string): string {
  return `https://sepolia.etherscan.io/address/${addr}`
}

type SafeTxParams = {
  to: string
  value: bigint
  data: string
  operation: number
  safeTxGas: bigint
  baseGas: bigint
  gasPrice: bigint
  gasToken: string
  refundReceiver: string
  nonce: bigint
}

function zeroGasParams(to: string, value: bigint, data: string, nonce: bigint): SafeTxParams {
  return { to, value, data, operation: 0, safeTxGas: 0n, baseGas: 0n, gasPrice: 0n, gasToken: ZERO, refundReceiver: ZERO, nonce }
}

async function signSafeTx(
  signer: Awaited<ReturnType<typeof ethers.getSigner>>,
  chainId: bigint,
  safeAddr: string,
  params: SafeTxParams,
): Promise<string> {
  return signer.signTypedData({ verifyingContract: safeAddr, chainId }, SAFE_TX_TYPES, params)
}

// Execute a Safe transaction with all gas params zeroed (standard for non-refund txs).
async function execSafeTx(
  safe: ethers.Contract,
  signer: Awaited<ReturnType<typeof ethers.getSigner>>,
  chainId: bigint,
  safeAddr: string,
  to: string,
  value: bigint,
  data: string,
  nonce: bigint,
): Promise<ethers.ContractTransactionReceipt> {
  const params = zeroGasParams(to, value, data, nonce)
  const sig = await signSafeTx(signer, chainId, safeAddr, params)
  const tx = await (safe.execTransaction as ethers.ContractMethod)(
    to,
    value,
    data,
    0,
    0n,
    0n,
    0n,
    ZERO,
    ZERO,
    sig,
    { gasLimit: 400_000n },
  )
  const receipt = await tx.wait()
  if (!receipt) throw new Error('execTransaction: null receipt')
  return receipt
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms))
}

// ── Main ──────────────────────────────────────────────────────────────────────

async function main() {
  const [deployer] = await ethers.getSigners()
  const deployerAddr = await deployer.getAddress()
  const { chainId } = await ethers.provider.getNetwork()

  console.log('\n══════════════════════════════════════════════════════════')
  console.log('  TimelockGuard — Sepolia lifecycle demo')
  console.log('══════════════════════════════════════════════════════════')
  console.log('Deployer :', deployerAddr)
  console.log('Guard    :', GUARD_ADDRESS, explorerAddr(GUARD_ADDRESS))
  console.log('ChainId  :', chainId.toString())

  const guard = TimelockGuard__factory.connect(GUARD_ADDRESS, deployer)

  // ── Step 1: Deploy Safe proxy ─────────────────────────────────────────────
  const safeL2Deployment = getSafeL2SingletonDeployment({ version: '1.4.1', network: String(chainId) })
  const proxyFactoryDeployment = getProxyFactoryDeployment({ version: '1.4.1', network: String(chainId) })

  if (!safeL2Deployment || !proxyFactoryDeployment) {
    throw new Error(`Safe v1.4.1 contracts not found in safe-deployments for chain ${chainId}`)
  }

  const singletonAddr = safeL2Deployment.networkAddresses[String(chainId)]
  const proxyFactoryAddr = proxyFactoryDeployment.networkAddresses[String(chainId)]

  if (!singletonAddr || !proxyFactoryAddr) {
    throw new Error(`Missing address for chain ${chainId} — check @safe-global/safe-deployments`)
  }

  const proxyFactory = new ethers.Contract(proxyFactoryAddr, SafeProxyFactoryArtifact.abi, deployer)
  const safeIface = new ethers.Interface(SafeArtifact.abi)

  // Encode Safe.setup() call: 1-of-1 with deployer as sole owner, no modules/fallback
  const initData = safeIface.encodeFunctionData('setup', [
    [deployerAddr], // owners
    1, // threshold
    ZERO, // to (no delegate call on setup)
    '0x', // data
    ZERO, // fallbackHandler
    ZERO, // paymentToken
    0, // payment
    ZERO, // paymentReceiver
  ])

  const salt = BigInt(Date.now())

  console.log('\n[1/7] Deploying 1-of-1 Safe proxy...')
  const proxyTxResp = await proxyFactory.createProxyWithNonce(singletonAddr, initData, salt, {
    gasLimit: 300_000n,
  })
  const proxyReceipt = (await proxyTxResp.wait()) as ethers.ContractTransactionReceipt
  if (!proxyReceipt) throw new Error('Proxy deployment: null receipt')

  // Decode Safe address from ProxyCreation event (proxy is an indexed address — lives in topics[1])
  const proxyCreationTopic = proxyFactory.interface.getEvent('ProxyCreation').topicHash
  const proxyLog = proxyReceipt.logs.find((l) => l.topics[0] === proxyCreationTopic)
  if (!proxyLog) throw new Error('ProxyCreation event not found in receipt')
  const [safeAddr] = ethers.AbiCoder.defaultAbiCoder().decode(['address'], proxyLog.topics[1])

  console.log('✔ Safe deployed  :', safeAddr)
  console.log('  Etherscan      :', explorerAddr(safeAddr))
  console.log('  Tx             :', explorerTx(proxyReceipt.hash))

  const safe = new ethers.Contract(safeAddr, SafeArtifact.abi, deployer)

  // ── Step 2: Fund the Safe ─────────────────────────────────────────────────
  // Safe needs ETH to execute the demo transfer. Send 2× the demo value for margin.
  console.log('\n[2/7] Funding Safe with', ethers.formatEther(DEMO_VALUE * 2n), 'ETH...')
  const fundTxResp = await deployer.sendTransaction({ to: safeAddr, value: DEMO_VALUE * 2n })
  const fundReceipt = await fundTxResp.wait()
  if (!fundReceipt) throw new Error('Fund tx: null receipt')
  console.log('✔ Funded')
  console.log('  Tx:', explorerTx(fundReceipt.hash))

  // ── Step 3: setUp(60) ─────────────────────────────────────────────────────
  // Guard is NOT installed yet — execTransaction runs without timelock checks.
  // The Safe itself calls setUp, satisfying the msg.sender == safe requirement.
  console.log('\n[3/7] Safe calls setUp(' + SETUP_DELAY + ') on guard (Safe nonce 0)...')
  const setUpData = guard.interface.encodeFunctionData('setUp', [SETUP_DELAY])
  const setUpReceipt = await execSafeTx(safe, deployer, chainId, safeAddr, GUARD_ADDRESS, 0n, setUpData, 0n)
  console.log('✔ Delay configured:', SETUP_DELAY.toString(), 'seconds')
  console.log('  Tx:', explorerTx(setUpReceipt.hash))

  // ── Step 4: setGuard ──────────────────────────────────────────────────────
  // After this tx, all Safe execTransactions are subject to the timelock.
  console.log('\n[4/7] Safe calls setGuard(guard) (Safe nonce 1)...')
  const setGuardData = safeIface.encodeFunctionData('setGuard', [GUARD_ADDRESS])
  const setGuardReceipt = await execSafeTx(safe, deployer, chainId, safeAddr, safeAddr, 0n, setGuardData, 1n)
  console.log('✔ Guard installed — all future execTransactions are timelocked')
  console.log('  Tx:', explorerTx(setGuardReceipt.hash))

  // ── Step 5: scheduleTransaction ──────────────────────────────────────────
  // Demo transaction: send DEMO_VALUE ETH back to the deployer. Safe nonce = 2.
  // Anyone may call scheduleTransaction — the guard verifies signatures on-chain.
  const demoNonce = 2n
  const demoParams = zeroGasParams(deployerAddr, DEMO_VALUE, '0x', demoNonce)
  const demoSig = await signSafeTx(deployer, chainId, safeAddr, demoParams)

  console.log('\n[5/7] Scheduling demo tx — send', ethers.formatEther(DEMO_VALUE), 'ETH to deployer (Safe nonce 2)...')
  const scheduleTxResp = await guard.scheduleTransaction(
    safeAddr,
    deployerAddr,
    DEMO_VALUE,
    '0x',
    0, // operation: CALL
    0n, // safeTxGas
    0n, // baseGas
    0n, // gasPrice
    ZERO, // gasToken
    ZERO, // refundReceiver
    demoNonce,
    demoSig,
    { gasLimit: 200_000n },
  )
  const scheduleReceipt = (await scheduleTxResp.wait()) as ethers.ContractTransactionReceipt
  if (!scheduleReceipt) throw new Error('scheduleTransaction: null receipt')

  // Parse readyAt from the TransactionScheduled event
  const scheduledTopic = guard.interface.getEvent('TransactionScheduled').topicHash
  const scheduleLog = scheduleReceipt.logs.find((l) => l.topics[0] === scheduledTopic)
  if (!scheduleLog) throw new Error('TransactionScheduled event not found')
  const parsedSchedule = guard.interface.parseLog({
    topics: scheduleLog.topics as string[],
    data: scheduleLog.data,
  })
  const readyAt: bigint = parsedSchedule!.args.readyAt
  const txHashScheduled: string = parsedSchedule!.args.txHash

  console.log('✔ Scheduled')
  console.log('  txHash  :', txHashScheduled)
  console.log('  readyAt :', new Date(Number(readyAt) * 1000).toISOString())
  console.log('  Tx      :', explorerTx(scheduleReceipt.hash))

  // ── Step 6: Wait ──────────────────────────────────────────────────────────
  const nowSec = BigInt(Math.floor(Date.now() / 1000))
  const waitSec = readyAt > nowSec ? Number(readyAt - nowSec) + 5 : 5
  console.log('\n[6/7] Waiting', waitSec, 'seconds for delay to elapse...')

  // Log countdown in 10-second intervals
  let remaining = waitSec
  while (remaining > 0) {
    const tick = Math.min(10, remaining)
    await sleep(tick * 1000)
    remaining -= tick
    if (remaining > 0) console.log('  ', remaining, 's remaining...')
  }
  console.log('✔ Delay elapsed')

  // ── Step 7: execTransaction ───────────────────────────────────────────────
  // The same signature used for scheduling is also valid for execution —
  // both cover the same EIP-712 SafeTx hash.
  console.log('\n[7/7] Executing scheduled tx...')
  const execTxResp = await (safe.execTransaction as ethers.ContractMethod)(
    deployerAddr,
    DEMO_VALUE,
    '0x',
    0,
    0n,
    0n,
    0n,
    ZERO,
    ZERO,
    demoSig,
    { gasLimit: 200_000n },
  )
  const execReceipt = (await execTxResp.wait()) as ethers.ContractTransactionReceipt
  if (!execReceipt) throw new Error('execTransaction: null receipt')
  console.log('✔ Executed —', ethers.formatEther(DEMO_VALUE), 'ETH delivered to deployer')
  console.log('  Tx:', explorerTx(execReceipt.hash))

  // ── Summary ───────────────────────────────────────────────────────────────
  console.log('\n══════════════════════════════════════════════════════════')
  console.log('  Summary — copy these into sepolia-evidence.md')
  console.log('══════════════════════════════════════════════════════════')
  console.log('Guard (pre-deployed) :', GUARD_ADDRESS)
  console.log('Safe (this run)      :', safeAddr)
  console.log('')
  console.log('Step 1 — Deploy Safe     :', proxyReceipt.hash)
  console.log('         Etherscan       :', explorerTx(proxyReceipt.hash))
  console.log('Step 2 — Fund Safe       :', fundReceipt.hash)
  console.log('         Etherscan       :', explorerTx(fundReceipt.hash))
  console.log('Step 3 — setUp           :', setUpReceipt.hash)
  console.log('         Etherscan       :', explorerTx(setUpReceipt.hash))
  console.log('Step 4 — setGuard        :', setGuardReceipt.hash)
  console.log('         Etherscan       :', explorerTx(setGuardReceipt.hash))
  console.log('Step 5 — schedule        :', scheduleReceipt.hash)
  console.log('         Etherscan       :', explorerTx(scheduleReceipt.hash))
  console.log('Step 6 — execute         :', execReceipt.hash)
  console.log('         Etherscan       :', explorerTx(execReceipt.hash))
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
