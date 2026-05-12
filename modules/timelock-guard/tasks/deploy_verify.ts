import { task } from 'hardhat/config'

// Placeholder — full deploy+verify task to be implemented in Week 3.
// See tasks/deploy/TimelockGuard.ts for the hardhat-deploy script.
task('deploy-timelock-guard', 'Deploys and verifies the TimelockGuard contract').setAction(async (_, hre) => {
  await hre.run('deploy', { tags: 'TimelockGuard' })
  await hre.run('etherscan-verify')
})
