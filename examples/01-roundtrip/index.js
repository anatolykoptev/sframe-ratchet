/**
 * 01-roundtrip — minimal Node.js SFrame encrypt/decrypt demo.
 *
 * Runs in Node 20+ with no browser required. Uses SimpleKex (shared password)
 * to derive a chain key, encrypts one frame as the sender, and decrypts it as
 * the receiver. Asserts the round-trip is lossless and prints hex + plaintext.
 *
 * WARNING: SimpleKex is for demos only. Do not use in production.
 */

import { SimpleKex } from 'sframe-ratchet/kex-simple';
import { deriveSenderKeys, sframeEncrypt, sframeDecrypt } from 'sframe-ratchet';

const SHARED_PASSWORD = 'demo-password-not-for-production';
const EPOCH = 0;
const PEER_INDEX = 0; // Alice is peer 0

// ── 1. Key exchange ─────────────────────────────────────────────────────────
// In a real deployment both sides run different KEX protocols (e.g. MLS).
// With SimpleKex they each derive the same chain key from the shared password.
const kexSender   = new SimpleKex({ sharedSecret: SHARED_PASSWORD });
const kexReceiver = new SimpleKex({ sharedSecret: SHARED_PASSWORD });

const ckSender   = await kexSender.initialEpoch();
const ckReceiver = await kexReceiver.initialEpoch();

// ── 2. Per-sender key derivation ─────────────────────────────────────────────
const senderKey   = await deriveSenderKeys(ckSender,   EPOCH, PEER_INDEX);
const receiverKey = await deriveSenderKeys(ckReceiver, EPOCH, PEER_INDEX);

// ── 3. Encrypt ───────────────────────────────────────────────────────────────
const plaintext  = new TextEncoder().encode('hello, sframe-ratchet!');
const ciphertext = await sframeEncrypt(plaintext, senderKey, /* CTR */ 0n);

console.log('=== sframe-ratchet 01-roundtrip ===\n');
console.log('Plaintext :', new TextDecoder().decode(plaintext));
console.log('Ciphertext:', Buffer.from(ciphertext).toString('hex'));

// ── 4. Decrypt ───────────────────────────────────────────────────────────────
const decrypted = await sframeDecrypt(
  ciphertext,
  ({ peerIndex }) => peerIndex === PEER_INDEX ? receiverKey : null,
);

const decoded = new TextDecoder().decode(decrypted);
console.log('Decrypted :', decoded);

// ── 5. Assert ────────────────────────────────────────────────────────────────
const original = new TextDecoder().decode(plaintext);
if (decoded !== original) {
  throw new Error(`Round-trip mismatch: got "${decoded}", expected "${original}"`);
}

console.log('\n✓ Round-trip OK');
