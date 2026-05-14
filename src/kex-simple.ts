// ⚠ WARNING — NOT FOR PRODUCTION ⚠
//
// SimpleKex is a reference key-exchange adapter that derives epoch chain keys
// from a shared password via PBKDF2 + HKDF.
//
// It intentionally has NO:
//   • Forward secrecy across compromise — one leaked password exposes every epoch.
//   • Membership consensus — anyone who knows the password can inject keys.
//   • Peer removal / revocation — leaving a peer does not invalidate existing keys.
//   • Compromise recovery — rotating the password requires out-of-band coordination.
//
// It EXISTS so library users can run a working demo in under 5 minutes without
// building a full key-exchange layer. Production deployments MUST replace it
// with MLS (e.g. @signalapp/libsignal-client, mls-rs), X3DH, or another real
// group-key-agreement protocol wired through the KeyChannel interface.

import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { CHAIN_KEY_BYTES } from './ratchet-crypto.ts';

// Default salt — a static constant so the library works out-of-the-box.
// Production MUST override with a unique random salt per room to prevent
// cross-room key reuse.
const DEFAULT_SALT = new TextEncoder().encode('sframe-ratchet/simple-kex/default-salt/v1');

// HKDF info prefix for epoch key derivation.
const EPOCH_INFO_PREFIX = 'sframe-simple-kex/epoch/';

/**
 * Configuration for {@link SimpleKex}.
 *
 * @remarks
 * **NOT FOR PRODUCTION** — see class-level warning.
 */
export interface SimpleKexConfig {
  /**
   * Shared password known to all participants.
   *
   * For testing, any string works. For a real deployment you MUST migrate to a
   * proper key-agreement protocol instead.
   */
  sharedSecret: string;

  /**
   * PBKDF2 salt. Defaults to a library-wide constant.
   *
   * Production users MUST supply a unique, randomly generated salt per room.
   * Reusing the default salt across rooms allows cross-room key correlation.
   */
  salt?: Uint8Array;

  /**
   * PBKDF2 iteration count. Defaults to 600_000.
   *
   * Lower values speed up tests but reduce brute-force resistance.
   * Do not lower below 100_000 in any code that touches real user data.
   */
  iterations?: number;
}

/**
 * Reference shared-password KEX adapter.
 *
 * @remarks
 * **⚠ NOT FOR PRODUCTION ⚠**
 *
 * SimpleKex derives epoch chain keys from a shared password:
 * - Epoch 0: `PBKDF2-SHA-256(password, salt, iterations)` → 32-byte ChainKey
 * - Epoch N: `HKDF-SHA-256(prevChainKey, info="sframe-simple-kex/epoch/{N}")` → 32-byte ChainKey
 *
 * This has **no forward secrecy**, **no membership consensus**, and **no
 * revocation**. It is suitable only for demos and local development.
 * Production deployments MUST plug in MLS or another real group-key-agreement
 * protocol through the library's KeyChannel interface.
 *
 * @example
 * ```ts
 * import { SimpleKex } from 'sframe-ratchet/kex-simple';
 * import { deriveSenderKeys, sframeEncrypt, sframeDecrypt } from 'sframe-ratchet';
 *
 * const kex = new SimpleKex({ sharedSecret: 'demo-password' });
 * const chainKey = await kex.initialEpoch();
 *
 * const aliceKey = await deriveSenderKeys(chainKey, 0, 0);
 * const bobKey   = await deriveSenderKeys(chainKey, 0, 1);
 *
 * const frame  = await sframeEncrypt(new TextEncoder().encode('hello'), aliceKey, 0n);
 * const opened = await sframeDecrypt(frame, ({ peerIndex }) => peerIndex === 0 ? aliceKey : null);
 * console.log(new TextDecoder().decode(opened)); // 'hello'
 * ```
 */
export class SimpleKex {
  private readonly _secret: string;
  private readonly _salt: Uint8Array;
  private readonly _iterations: number;

  constructor(config: SimpleKexConfig) {
    if (!config.sharedSecret) {
      throw new TypeError('SimpleKex: sharedSecret must be a non-empty string');
    }
    this._secret = config.sharedSecret;
    this._salt = config.salt ?? DEFAULT_SALT;
    this._iterations = config.iterations ?? 600_000;

    if (this._iterations < 1) {
      throw new RangeError('SimpleKex: iterations must be >= 1');
    }
  }

  /**
   * Derive the initial chain key (epoch 0) from the shared password via
   * PBKDF2-SHA-256.
   *
   * @returns 32-byte chain key suitable for {@link deriveSenderKeys}.
   *
   * @remarks **NOT FOR PRODUCTION** — see class-level warning.
   */
  async initialEpoch(): Promise<Uint8Array> {
    const password = new TextEncoder().encode(this._secret);
    const derived = await pbkdf2Async(sha256, password, this._salt, {
      c: this._iterations,
      dkLen: CHAIN_KEY_BYTES,
    });
    return derived;
  }

  /**
   * Derive the chain key for epoch `newEpoch` from the previous epoch's chain
   * key via HKDF-SHA-256.
   *
   * Domain-separated by epoch number so each epoch yields distinct key
   * material even if the chain keys were somehow observed.
   *
   * @param prev      32-byte chain key from epoch `newEpoch - 1`.
   * @param newEpoch  The epoch number being advanced to (>= 1).
   * @returns 32-byte chain key for the new epoch.
   *
   * @remarks **NOT FOR PRODUCTION** — see class-level warning.
   */
  rotateEpoch(prev: Uint8Array, newEpoch: number): Uint8Array {
    if (prev.length !== CHAIN_KEY_BYTES) {
      throw new TypeError(
        `SimpleKex: prev chain key must be ${CHAIN_KEY_BYTES} bytes, got ${prev.length}`,
      );
    }
    if (!Number.isInteger(newEpoch) || newEpoch < 1) {
      throw new RangeError(`SimpleKex: newEpoch must be an integer >= 1, got ${newEpoch}`);
    }
    const info = new TextEncoder().encode(`${EPOCH_INFO_PREFIX}${newEpoch}`);
    return hkdf(sha256, prev, undefined, info, CHAIN_KEY_BYTES);
  }
}
