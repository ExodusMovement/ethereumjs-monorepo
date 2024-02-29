import tape from 'tape'
import Common, { Chain, Hardfork } from '@exodus/ethereumjs-common'
import {
  Transaction,
  AccessListEIP2930Transaction,
  FeeMarketEIP1559Transaction,
  N_DIV_2,
  Capability,
} from '../src'
import { TxsJsonEntry } from './types'
import { BaseTransaction } from '../src/baseTransaction'
import { privateToPublic, BN, toBuffer } from '@exodus/ethereumjs-util'
import { ecdsaSign } from '@exodus/secp256k1'

tape('[BaseTransaction with signer]', function (t) {
  // EIP-2930 is not enabled in Common by default (2021-03-06)
  const common = new Common({ chain: Chain.Mainnet, hardfork: Hardfork.London })

  const legacyFixtures: TxsJsonEntry[] = require('./json/txs.json')
  const legacyTxs: BaseTransaction<Transaction>[] = []
  legacyFixtures.slice(0, 4).forEach(function (tx: TxsJsonEntry) {
    legacyTxs.push(Transaction.fromTxData(tx.data, { common }))
  })

  const eip2930Fixtures = require('./json/eip2930txs.json')
  const eip2930Txs: BaseTransaction<AccessListEIP2930Transaction>[] = []
  eip2930Fixtures.forEach(function (tx: any) {
    eip2930Txs.push(AccessListEIP2930Transaction.fromTxData(tx.data, { common }))
  })

  const eip1559Fixtures = require('./json/eip1559txs.json')
  const eip1559Txs: BaseTransaction<FeeMarketEIP1559Transaction>[] = []
  eip1559Fixtures.forEach(function (tx: any) {
    eip1559Txs.push(FeeMarketEIP1559Transaction.fromTxData(tx.data, { common }))
  })

  const zero = Buffer.alloc(0)
  const txTypes = [
    {
      class: Transaction,
      name: 'Transaction',
      type: 0,
      values: Array(6).fill(zero),
      txs: legacyTxs,
      fixtures: legacyFixtures,
      activeCapabilities: [],
      notActiveCapabilities: [
        Capability.EIP1559FeeMarket,
        Capability.EIP2718TypedTransaction,
        Capability.EIP2930AccessLists,
        9999,
      ],
    },
    {
      class: AccessListEIP2930Transaction,
      name: 'AccessListEIP2930Transaction',
      type: 1,
      values: [Buffer.from([1])].concat(Array(7).fill(zero)),
      txs: eip2930Txs,
      fixtures: eip2930Fixtures,
      activeCapabilities: [Capability.EIP2718TypedTransaction, Capability.EIP2930AccessLists],
      notActiveCapabilities: [Capability.EIP1559FeeMarket, 9999],
    },
    {
      class: FeeMarketEIP1559Transaction,
      name: 'FeeMarketEIP1559Transaction',
      type: 2,
      values: [Buffer.from([1])].concat(Array(8).fill(zero)),
      txs: eip1559Txs,
      fixtures: eip1559Fixtures,
      activeCapabilities: [
        Capability.EIP1559FeeMarket,
        Capability.EIP2718TypedTransaction,
        Capability.EIP2930AccessLists,
      ],
      notActiveCapabilities: [9999],
    },
  ]

  t.test('signWithSigner()', async function (st) {
    for (const txType of txTypes) {
      let i = 0
      for (const tx of txType.txs) {
        const { privateKey } = txType.fixtures[i++]

        if (privateKey) {
          const signer = async (buffer: Buffer): Promise<any> => {
            const s = ecdsaSign(buffer, Buffer.from(privateKey, 'hex'))
            console.log(`${privateKey}`, {
              signature: Buffer.from(s.signature).toString('hex'),
              buffer: buffer.toString('hex'),
              recid: s.recid,
            })
            return s
          }

          st.ok(await tx.signWithSigner(signer), `${txType.name}: should sign tx`)
        }

        st.throws(
          () => tx.sign(Buffer.from('invalid')),
          `${txType.name}: should fail with invalid PK`
        )
      }
    }
    st.end()
  })
})
