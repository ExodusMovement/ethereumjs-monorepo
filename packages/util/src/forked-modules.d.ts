declare module '@exodus/secp256k1' {
  export * from 'secp256k1';
  import secp256k1 from 'secp256k1';
  export default secp256k1;
}

declare module '@exodus/keccak' {
  export * from 'keccak';
  import keccak from 'keccak';
  export default keccak;
}
