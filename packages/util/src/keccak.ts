// Compatible with https://www.npmjs.com/package/ethereum-cryptography

/// <reference path="forked-modules.d.ts"/>
import { default as createKeccakHash, KeccakAlgorithm } from '@exodus/keccak'

function createHashFunction(algorithm: KeccakAlgorithm): (msg: Buffer) => Buffer {
  return msg => {
    const hash = createKeccakHash(algorithm)
    hash.update(msg)
    return Buffer.from(hash.digest())
  }
}

export const keccak224 = createHashFunction('keccak224')
export const keccak256 = createHashFunction('keccak256')
export const keccak384 = createHashFunction('keccak384')
export const keccak512 = createHashFunction('keccak512')
