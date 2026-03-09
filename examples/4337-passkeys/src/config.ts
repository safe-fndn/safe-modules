import { getMultiSendDeployment, getProxyFactoryDeployment, getSafeL2SingletonDeployment } from '@safe-global/safe-deployments'
import { getSafe4337ModuleDeployment, getSafeModuleSetupDeployment } from '@safe-global/safe-modules-deployments'

// 11155111 = Sepolia testnet chain id
const APP_CHAIN_ID = 11155111

// Sep testnet shortname
// https://eips.ethereum.org/EIPS/eip-3770
const APP_CHAIN_SHORTNAME = 'sep'

type DeploymentFunction = (filter: { network: string }) => { networkAddresses: Record<string, string | undefined> } | undefined
function getDeploymentAddress(fn: DeploymentFunction) {
  const network = `${APP_CHAIN_ID}`
  const deployment = fn({ network })
  if (!deployment || !deployment.networkAddresses[network]) {
    throw new Error('deployment not found')
  }
  return deployment.networkAddresses[network]
}

/*
  The Safe WebAuthn shared signer is still not audited and not included in the production deployment
  packages, thus we need to hardcode their addresses here.
  Deployment tag: https://github.com/safe-global/safe-modules/tree/passkey/v0.2.0
*/
const SAFE_WEBAUTHN_SHARED_SIGNER_ADDRESS = '0xfD90FAd33ee8b58f32c00aceEad1358e4AFC23f9'

const SAFE_MULTISEND_ADDRESS = getDeploymentAddress(getMultiSendDeployment)

const SAFE_4337_MODULE_ADDRESS = getDeploymentAddress(getSafe4337ModuleDeployment)

const SAFE_MODULE_SETUP_ADDRESS = getDeploymentAddress(getSafeModuleSetupDeployment)

// Daimo P256 verifier deployed at a canonical address across all EVM chains via CREATE2.
// https://github.com/daimo-eth/p256-verifier
const P256_VERIFIER_ADDRESS = '0xc2b78104907F722DABAc4C69f826a522B2754De4'

const SAFE_PROXY_FACTORY_ADDRESS = getDeploymentAddress(getProxyFactoryDeployment)

const SAFE_SINGLETON_ADDRESS = getDeploymentAddress(getSafeL2SingletonDeployment)

const ENTRYPOINT_ADDRESS = '0x0000000071727De22E5E9d8BAf0edAc6f37da032'

const XANDER_BLAZE_NFT_ADDRESS = '0xBb9ebb7b8Ee75CDBf64e5cE124731A89c2BC4A07'

export {
  SAFE_MODULE_SETUP_ADDRESS,
  APP_CHAIN_ID,
  ENTRYPOINT_ADDRESS,
  SAFE_MULTISEND_ADDRESS,
  SAFE_WEBAUTHN_SHARED_SIGNER_ADDRESS,
  SAFE_4337_MODULE_ADDRESS,
  SAFE_PROXY_FACTORY_ADDRESS,
  SAFE_SINGLETON_ADDRESS,
  XANDER_BLAZE_NFT_ADDRESS,
  P256_VERIFIER_ADDRESS,
  APP_CHAIN_SHORTNAME,
}
