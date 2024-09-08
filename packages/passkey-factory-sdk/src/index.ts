import { Buffer } from "buffer";
import { Address } from '@stellar/stellar-sdk';
import {
  AssembledTransaction,
  Client as ContractClient,
  ClientOptions as ContractClientOptions,
  Result,
  Spec as ContractSpec,
} from '@stellar/stellar-sdk/contract';
import type {
  u32,
  i32,
  u64,
  i64,
  u128,
  i128,
  u256,
  i256,
  Option,
  Typepoint,
  Duration,
} from '@stellar/stellar-sdk/contract';

if (typeof window !== 'undefined') {
  //@ts-ignore Buffer exists
  window.Buffer = window.Buffer || Buffer;
}


export const networks = {
  testnet: {
    networkPassphrase: "Test SDF Network ; September 2015",
    contractId: "CDGB6ADQPTZOVIYKITZK2P3J2UGZSHTV7KXHIG2OTLS2J4N65NL5FYGC",
  }
} as const

export const Errors = {
  1: { message: "NotInitialized" },

  2: { message: "AlreadyInitialized" }
}
export type Ed25519PublicKey = readonly [Buffer];
export type Secp256r1Id = readonly [Buffer];
export type Signer = { tag: "Ed25519", values: readonly [Ed25519PublicKey] } | { tag: "Secp256r1", values: readonly [Secp256r1Id] };


export interface Client {
  /**
   * Construct and simulate a init transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  init: ({ wasm_hash }: { wasm_hash: Buffer }, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Result<void>>>

  /**
   * Construct and simulate a deploy transaction. Returns an `AssembledTransaction` object which will have a `result` field containing the result of the simulation. If this transaction changes contract state, you will need to call `signAndSend()` on the returned object.
   */
  deploy: ({ salt, id, pk }: { salt: Buffer, id: Signer, pk: Option<Buffer> }, options?: {
    /**
     * The fee to pay for the transaction. Default: BASE_FEE
     */
    fee?: number;

    /**
     * The maximum amount of time to wait for the transaction to complete. Default: DEFAULT_TIMEOUT
     */
    timeoutInSeconds?: number;

    /**
     * Whether to automatically simulate the transaction when constructing the AssembledTransaction. Default: true
     */
    simulate?: boolean;
  }) => Promise<AssembledTransaction<Result<string>>>

}
export class Client extends ContractClient {
  constructor(public readonly options: ContractClientOptions) {
    super(
      new ContractSpec(["AAAABAAAAAAAAAAAAAAABUVycm9yAAAAAAAAAgAAAAAAAAAOTm90SW5pdGlhbGl6ZWQAAAAAAAEAAAAAAAAAEkFscmVhZHlJbml0aWFsaXplZAAAAAAAAg==",
        "AAAAAQAAAAAAAAAAAAAAEEVkMjU1MTlQdWJsaWNLZXkAAAABAAAAAAAAAAEwAAAAAAAD7gAAACA=",
        "AAAAAQAAAAAAAAAAAAAAC1NlY3AyNTZyMUlkAAAAAAEAAAAAAAAAATAAAAAAAAAO",
        "AAAAAgAAAAAAAAAAAAAABUtleUlkAAAAAAAAAgAAAAEAAAAAAAAAB0VkMjU1MTkAAAAAAQAAB9AAAAAQRWQyNTUxOVB1YmxpY0tleQAAAAEAAAAAAAAACVNlY3AyNTZyMQAAAAAAAAEAAAfQAAAAC1NlY3AyNTZyMUlkAA==",
        "AAAAAAAAAAAAAAAEaW5pdAAAAAEAAAAAAAAACXdhc21faGFzaAAAAAAAA+4AAAAgAAAAAQAAA+kAAAPtAAAAAAAAAAM=",
        "AAAAAAAAAAAAAAAGZGVwbG95AAAAAAADAAAAAAAAAARzYWx0AAAD7gAAACAAAAAAAAAAAmlkAAAAAAfQAAAABUtleUlkAAAAAAAAAAAAAAJwawAAAAAD6AAAA+4AAABBAAAAAQAAA+kAAAATAAAAAw=="]),
      options
    )
  }
  public readonly fromJSON = {
    init: this.txFromJSON<Result<void>>,
    deploy: this.txFromJSON<Result<string>>
  }
}