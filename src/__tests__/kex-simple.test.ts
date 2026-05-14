// Tests for SimpleKex — reference shared-password KEX adapter.
// Verifies: determinism, isolation, epoch rotation, parameter handling,
// and end-to-end integration with the sframe encrypt/decrypt path.

import { describe, expect, it } from 'vitest';
import { SimpleKex } from '../kex-simple.ts';
import { deriveSenderKeys, sframeDecrypt, sframeEncrypt } from '../index.ts';
import { CHAIN_KEY_BYTES } from '../ratchet-crypto.ts';

// ---- Helpers ---------------------------------------------------------------

const FAST_ITER = 1_000; // Keep unit tests fast; don't use in real code.
const SALT_A = new Uint8Array(32).fill(0x01);
const SALT_B = new Uint8Array(32).fill(0x02);

function makeKex(overrides: Partial<ConstructorParameters<typeof SimpleKex>[0]> = {}): SimpleKex {
  return new SimpleKex({ sharedSecret: 'test-password', iterations: FAST_ITER, ...overrides });
}

// ---- Determinism -----------------------------------------------------------

describe('initialEpoch — determinism', () => {
  it('same password + salt → same chain key', async () => {
    const kex = makeKex({ salt: SALT_A });
    const [k1, k2] = await Promise.all([kex.initialEpoch(), kex.initialEpoch()]);
    expect(k1).toStrictEqual(k2);
  });

  it('different salt → different chain key', async () => {
    const k1 = await makeKex({ salt: SALT_A }).initialEpoch();
    const k2 = await makeKex({ salt: SALT_B }).initialEpoch();
    expect(k1).not.toStrictEqual(k2);
  });

  it('different password → different chain key', async () => {
    const k1 = await makeKex({ sharedSecret: 'password-one', salt: SALT_A }).initialEpoch();
    const k2 = await makeKex({ sharedSecret: 'password-two', salt: SALT_A }).initialEpoch();
    expect(k1).not.toStrictEqual(k2);
  });

  it('initial epoch output is exactly CHAIN_KEY_BYTES long', async () => {
    const k = await makeKex({ salt: SALT_A }).initialEpoch();
    expect(k.byteLength).toBe(CHAIN_KEY_BYTES);
  });
});

// ---- Epoch rotation --------------------------------------------------------

describe('rotateEpoch — correctness', () => {
  it('rotate epoch 0 → 1 → 2: each chain key is distinct', async () => {
    const kex = makeKex({ salt: SALT_A });
    const ck0 = await kex.initialEpoch();
    const ck1 = kex.rotateEpoch(ck0, 1);
    const ck2 = kex.rotateEpoch(ck1, 2);

    expect(ck1).not.toStrictEqual(ck0);
    expect(ck2).not.toStrictEqual(ck1);
    expect(ck2).not.toStrictEqual(ck0);
  });

  it('rotateEpoch is deterministic for (prev, newEpoch)', async () => {
    const kex = makeKex({ salt: SALT_A });
    const ck0 = await kex.initialEpoch();
    const a = kex.rotateEpoch(ck0, 1);
    const b = kex.rotateEpoch(ck0, 1);
    expect(a).toStrictEqual(b);
  });

  it('rotateEpoch output is exactly CHAIN_KEY_BYTES long', async () => {
    const kex = makeKex({ salt: SALT_A });
    const ck0 = await kex.initialEpoch();
    const ck1 = kex.rotateEpoch(ck0, 1);
    expect(ck1.byteLength).toBe(CHAIN_KEY_BYTES);
  });

  it('two instances with same password derive matching chain keys at each epoch', async () => {
    const kexAlice = makeKex({ salt: SALT_A });
    const kexBob = makeKex({ salt: SALT_A });

    const a0 = await kexAlice.initialEpoch();
    const b0 = await kexBob.initialEpoch();
    expect(a0).toStrictEqual(b0);

    const a1 = kexAlice.rotateEpoch(a0, 1);
    const b1 = kexBob.rotateEpoch(b0, 1);
    expect(a1).toStrictEqual(b1);

    const a2 = kexAlice.rotateEpoch(a1, 2);
    const b2 = kexBob.rotateEpoch(b1, 2);
    expect(a2).toStrictEqual(b2);
  });
});

// ---- Iterations parameter --------------------------------------------------

describe('iterations parameter', () => {
  it('accepts iterations=1 (does not crash)', async () => {
    const kex = new SimpleKex({ sharedSecret: 'pw', iterations: 1 });
    const k = await kex.initialEpoch();
    expect(k.byteLength).toBe(CHAIN_KEY_BYTES);
  });

  it('higher iterations produces different key material than lower', async () => {
    const k1 = await new SimpleKex({ sharedSecret: 'pw', salt: SALT_A, iterations: 1 }).initialEpoch();
    const k2 = await new SimpleKex({ sharedSecret: 'pw', salt: SALT_A, iterations: 2 }).initialEpoch();
    // PBKDF2 with different c values should produce different output.
    expect(k1).not.toStrictEqual(k2);
  });
});

// ---- Input validation ------------------------------------------------------

describe('constructor validation', () => {
  it('throws TypeError on empty sharedSecret', () => {
    expect(() => new SimpleKex({ sharedSecret: '' })).toThrow(TypeError);
  });

  it('throws RangeError on iterations < 1', () => {
    expect(() => new SimpleKex({ sharedSecret: 'pw', iterations: 0 })).toThrow(RangeError);
  });
});

describe('rotateEpoch validation', () => {
  it('throws RangeError when newEpoch < 1', async () => {
    const kex = makeKex({ salt: SALT_A });
    const ck0 = await kex.initialEpoch();
    expect(() => kex.rotateEpoch(ck0, 0)).toThrow(RangeError);
  });

  it('throws TypeError on wrong-length prev key', () => {
    const kex = makeKex({ salt: SALT_A });
    expect(() => kex.rotateEpoch(new Uint8Array(16), 1)).toThrow(TypeError);
  });
});

// ---- End-to-end: two parties encrypt/decrypt a frame -----------------------

describe('end-to-end: Alice encrypts, Bob decrypts', () => {
  it('same password → encrypt+decrypt succeeds', async () => {
    const EPOCH = 0;
    const ALICE_INDEX = 0;

    // Both parties derive the same initial chain key.
    const kexAlice = makeKex({ salt: SALT_A });
    const kexBob = makeKex({ salt: SALT_A });

    const ckAlice = await kexAlice.initialEpoch();
    const ckBob = await kexBob.initialEpoch();

    // Chain keys are equal — both peers agree on key material.
    expect(ckAlice).toStrictEqual(ckBob);

    // Derive Alice's sending key.
    const aliceKey = await deriveSenderKeys(ckAlice, EPOCH, ALICE_INDEX);

    // Alice encrypts.
    const plaintext = new TextEncoder().encode('hello from SimpleKex');
    const sealed = await sframeEncrypt(plaintext, aliceKey, 0n);

    // Bob derives the same key from his copy and decrypts.
    const aliceKeyBob = await deriveSenderKeys(ckBob, EPOCH, ALICE_INDEX);
    const opened = await sframeDecrypt(sealed, ({ peerIndex }) =>
      peerIndex === ALICE_INDEX ? aliceKeyBob : null,
    );

    expect(new TextDecoder().decode(opened)).toBe('hello from SimpleKex');
  });

  it('different passwords → decryption fails (AEAD tag mismatch)', async () => {
    const EPOCH = 0;
    const ALICE_INDEX = 0;

    const ckAlice = await makeKex({ sharedSecret: 'correct-horse', salt: SALT_A }).initialEpoch();
    const ckBob = await makeKex({ sharedSecret: 'wrong-password', salt: SALT_A }).initialEpoch();

    const aliceKey = await deriveSenderKeys(ckAlice, EPOCH, ALICE_INDEX);
    const bobWrongKey = await deriveSenderKeys(ckBob, EPOCH, ALICE_INDEX);

    const sealed = await sframeEncrypt(new TextEncoder().encode('secret'), aliceKey, 0n);

    await expect(
      sframeDecrypt(sealed, () => bobWrongKey),
    ).rejects.toThrow();
  });
});
