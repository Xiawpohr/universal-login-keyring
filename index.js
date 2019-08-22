const EventEmitter = require('events').EventEmitter
const Wallet = require('ethereumjs-wallet')
const ethUtil = require('ethereumjs-util')
const sigUtil = require('eth-sig-util')

const type = 'Universal Login Wallet Keyring'

class ContractWalletKeyring extends EventEmitter {

  constructor (options) {
    super()
    this.type = type
    this.proxies = {} // proxyAddress: [ownerWallets]
    this.deserialize(options)
  }

  // PUBLIC METHODS
  
  serialize () {
    const serialized = Object.keys(this.proxies).reduce((proxies, address) => {
      const privateKeys = this.proxies[address].map(wallet => wallet.getPrivateKey().toString('hex'))
      return { ...proxies, [address]: [...privateKeys]}
    }, {})
    return Promise.resolve(serialized)
  }

  deserialize (options = {}) {
    return new Promise((resolve, reject) => {
      try {
        this.proxies = Object.keys(options).reduce((proxies, address) => {
          const wallets = options[address].map(privateKey => {
            const stripped = ethUtil.stripHexPrefix(privateKey)
            const buffer = new Buffer(stripped, 'hex')
            const wallet = Wallet.fromPrivateKey(buffer)
            return wallet
          })
          return { ...proxies, [address]: [...wallets] }
        }, {})
      } catch (e) {
        reject(e)
      }
      resolve()
    })
  }

  addAccounts (n = 1) {
    const newProxies = {}
    for (let i = 1; i < n; i++) {
      const wallet = Wallet.generate()
      newProxies[wallet.getAddress()] = [wallet.getPrivateKey()]
    }
    this.proxies = { ...this.proxies, newProxies }
    return Promise.resolve(Object.keys(this.proxies))
  }

  getAccounts () {
    return Promise.resolve(Object.keys(this.proxies))
  }

  signTransaction (address, transaction) {
    const wallets = this._getWalletsForAccount(address)
    if (!wallets.length) throw new Error('Private keys does not exist.')
    const privateKey = wallets[0].getPrivateKey()
    transaction.sign(privateKey)
    return Promise.resolve(transaction)
  }
  
  signMessage (address, data) {
    const wallets = this._getWalletsForAccount(address)
    if (!wallets.length) throw new Error('Private keys does not exist.')
    const message = ethUtil.stripHexPrefix(data)
    const privateKey = wallets[0].getPrivateKey()
    const signature = ethUtil.ecsign(new Buffer(message, 'hex'), privateKey)
    const rawSignature = ethUtil.bufferToHex(sigUtil.concatSig(signature.v, signature.r, signature.s))
    return Promise.resolve(rawSignature)
  }

  exportAccount () {
    return Promise.reject(new Error('Not supported on this contract wallet'))
  }

  // PRIVATE METHODS

  _getWalletsForAccount (account) {
    const address = sigUtil.normalize(account)
    const wallets = this.proxies[address]
    if (!wallets) throw new Error('Contract Wallet Keyring - Unable to find matching address.')
    return wallets
  }
}

ContractWalletKeyring.type = type
module.exports = ContractWalletKeyring
