import { task } from 'hardhat/config'

// Placeholder — full deploy+verify task to be implemented in Week 3.
// See tasks/deploy/TimelockGuard.ts for the hardhat-deploy script.
task('deploy-timelock-guard', 'Deploys and verifies the TimelockGuard contract').setAction(async (_, hre) => {
  await hre.run('deploy', { tags: 'TimelockGuard' })
  // LGPL-3.0-only is the correct SPDX form but Etherscan only accepts LGPL-3.0
  await hre.run('etherscan-verify', { forceLicense: true, license: 'LGPL-3.0' })
})
