# sframe-ratchet

[![npm](https://img.shields.io/npm/v/sframe-ratchet)](https://www.npmjs.com/package/sframe-ratchet)
[![CI](https://github.com/anatolykoptev/sframe-ratchet/actions/workflows/ci.yml/badge.svg)](https://github.com/anatolykoptev/sframe-ratchet/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-green)](./LICENSE)

RFC 9605 SFrame AEAD with an epoch ratchet and Web Worker pipeline, for group end-to-end encryption in browser WebRTC.

## Why this exists

When several browsers join an SFU-routed call, the SFU is in the media path. TLS/DTLS protects the hop between each peer and the SFU, but the SFU itself sees plaintext frames. Group E2EE closes that gap: every encoded media frame is encrypted with a per-sender key before it leaves the browser, and the SFU forwards only opaque payloads. SFrame ([RFC 9605](https://www.rfc-editor.org/rfc/rfc9605.html)) is the IETF frame format for that pattern, designed to survive SFU rewrites without breaking authentication.

SFrame on its own does not say where keys come from. A ratchet on top provides forward secrecy and clean key rotation when members join or leave: each membership change advances the room to a new epoch with fresh per-sender keys, and old epoch material is wiped after a brief grace window so in-flight frames still decode. Without this, a compromised long-term key would retroactively expose every recorded frame.

Existing implementations cover parts of the problem but not the whole:

| Implementation         | SFrame AEAD | Ratchet | Browser-native | Standalone package |
|------------------------|-------------|---------|----------------|--------------------|
| [`cisco/sframe`](https://github.com/cisco/sframe) | yes | no | C++ only | C++ library |
| [Medooze `sframe`](https://www.npmjs.com/package/sframe) | yes | no | yes | yes |
| [`@telnyx/sframe`](https://www.npmjs.com/package/@telnyx/sframe) | yes | no | yes | yes (unmaintained) |
| LiveKit client SDK     | yes | yes | yes | no (bundled in SDK) |
| **`sframe-ratchet`**   | yes | yes | yes | yes |

`sframe-ratchet` packages all three pieces — RFC 9605 AEAD, an epoch ratchet, and the Web Worker pipeline that keeps `CryptoKey` objects off the main thread — as a standalone TypeScript module with no transport dependencies.

## Features

- RFC 9605 SFrame frame format and AES-GCM AEAD
- **AES-128 and AES-256 cipher suites (RFC 9605 §4.5):** suite 4 (`AES_128_GCM_SHA256`, default) and suite 5 (`AES_256_GCM_SHA512`) — select per room
- Epoch ratchet: per-sender chain-key derivation, epoch rotation, 5-second grace period for in-flight frames from the prior epoch
- Web Worker pipeline that isolates `CryptoKey` material from the main thread (via `RTCRtpScriptTransform` when available, `createEncodedStreams` as fallback)
- X25519 key agreement via WebCrypto with a `@noble/curves` fallback for runtimes that lack it
- Zero transport dependencies — bring your own key exchange and signaling
- Browser-first; Node 20+ supported for tests

### FIPS / HIPAA

Suite 5 (`AES_256_GCM_SHA512`) uses AES-256-GCM (FIPS 197) and HKDF-SHA-512 (NIST SP 800-56C). Suite 4 (`AES_128_GCM_SHA256`) uses AES-128-GCM and HKDF-SHA-256, also NIST-approved. All cryptographic operations use the host platform's WebCrypto (`crypto.subtle`); FIPS 140-2/140-3 validation status depends on the runtime's WebCrypto implementation.

```ts
import { RoomRatchet, newIdentity } from 'sframe-ratchet';

// AES-256 for HIPAA / high-assurance deployments
const ratchet = new RoomRatchet({
  identity: newIdentity('alice'),
  suite: 'AES_256_GCM_SHA512',
});
```

## Install

```bash
npm install sframe-ratchet @noble/curves @noble/hashes
```

`@noble/curves` and `@noble/hashes` are peer dependencies — declared explicitly so you control their version.

## Quick start

### Hello world with SimpleKex (NOT for production)

> **⚠ SimpleKex is for demos and local development only.** It has no forward secrecy, no membership consensus, and no revocation. See `src/kex-simple.ts` and the class-level JSDoc for the full warning. For production, see "Production: bring your own KEX" below.

```ts
import { SimpleKex } from 'sframe-ratchet/kex-simple';
import { deriveSenderKeys, sframeEncrypt, sframeDecrypt } from 'sframe-ratchet';

// Both peers share the same password and salt (set a random per-room salt in real use).
const kexAlice = new SimpleKex({ sharedSecret: 'demo-password' });
const kexBob   = new SimpleKex({ sharedSecret: 'demo-password' });

// Derive epoch 0 chain key — identical on both sides from the same password.
const ckAlice = await kexAlice.initialEpoch();
const ckBob   = await kexBob.initialEpoch();

// Each peer derives its own sending key from the shared chain key.
const aliceKey = await deriveSenderKeys(ckAlice, /* epoch */ 0, /* peerIndex */ 0);
const aliceKeyBob = await deriveSenderKeys(ckBob, /* epoch */ 0, /* peerIndex */ 0);

// Alice encrypts; Bob decrypts using his copy of the same key.
const sealed = await sframeEncrypt(new TextEncoder().encode('hello!'), aliceKey, 0n);
const opened = await sframeDecrypt(sealed, ({ peerIndex }) => peerIndex === 0 ? aliceKeyBob : null);
console.log(new TextDecoder().decode(opened)); // 'hello!'

// Rotate to epoch 1 (e.g. on membership change).
const ck1Alice = kexAlice.rotateEpoch(ckAlice, 1);
```

### Production: bring your own KEX

For production, replace `SimpleKex` with a real key-agreement protocol. The library is KEX-agnostic — any mechanism that produces a shared ChainKey per epoch integrates with `deriveSenderKeys`. The ChainKey size is suite-dependent: 32 bytes for suite 4 (SHA-256), 64 bytes for suite 5 (SHA-512).

- **MLS**: use `@signalapp/libsignal-client` or `mls-rs` to negotiate epoch keys; extract the appropriate number of bytes via your exporter and pass them as the `chainKey` argument.
- **X3DH**: perform the handshake off-band, derive a shared secret, and feed it through `HKDF` to your `chainKey`.
- **Custom ECDH**: wrap your DH output in `HKDF-SHA-256` to produce 32 uniform bytes.

The `EpochAnnouncement` / `RoomRatchet` API in this library handles the per-epoch key-table bookkeeping once you supply the chain key material.

### Low-level path

The lowest-level path: derive per-sender keys from a shared chain key, then encrypt and decrypt a single frame.

```ts
import {
  deriveSenderKeys,
  randomChainKey,
  sframeEncrypt,
  sframeDecrypt,
} from 'sframe-ratchet';

// In a real deployment the chain key is delivered to each peer through
// your key-exchange protocol. Here we generate one locally for the demo.
const chainKey = randomChainKey();

// Two peers in the same epoch get distinct peer_index values.
// Both peers derive identical key tables from the shared chain key.
const alice = await deriveSenderKeys(chainKey, /* epoch */ 1, /* peerIndex */ 0);
const bob   = await deriveSenderKeys(chainKey, /* epoch */ 1, /* peerIndex */ 1);

// Alice encrypts a frame with a monotonic counter she keeps per epoch.
const plaintext = new TextEncoder().encode('hello sframe');
const sealed = await sframeEncrypt(plaintext, alice, /* ctr */ 7n);

// Bob receives `sealed`, reads the KID from the header, and looks up the
// key for (epoch, peerIndex). The resolver is also where stale-epoch and
// unknown-sender policies live.
const opened = await sframeDecrypt(sealed, ({ kid, epoch, peerIndex }) => {
  if (epoch !== 1) return null;          // stale epoch -> drop
  if (peerIndex === 0) return alice;     // Alice's key from bob's table
  return null;
});

console.log(new TextDecoder().decode(opened)); // -> 'hello sframe'
```

For a full room, use `RoomRatchet` to manage the epoch lifecycle and `FrameCryptor` to wire the worker to `RTCRtpSender` / `RTCRtpReceiver`:

```ts
import { RoomRatchet, FrameCryptor, newIdentity } from 'sframe-ratchet';

const identity = await newIdentity('alice');             // X25519 keypair
const ratchet  = new RoomRatchet({ identity });

// On membership change, the authoritative author mints a new epoch and
// returns one EpochAnnouncement per other member. You ship those over
// your own DataChannel / signaling channel.
const announcements = await ratchet.startNewEpoch([
  { peerId: 'bob',     publicKey: bobPub },
  { peerId: 'charlie', publicKey: charliePub },
]);
for (const a of announcements) await yourSignaling.send(a.forPeer, a);

// Receivers consume announcements addressed to them.
yourSignaling.on('epoch_new', (msg) => ratchet.consumeEpochAnnouncement(msg));

// Hook the worker into an RTCPeerConnection sender.
const worker   = new Worker(new URL('sframe-ratchet/worker', import.meta.url), { type: 'module' });
const cryptor  = new FrameCryptor({ worker, role: 'sender', peerId: 'alice', peerIndex: 0 });
cryptor.attachSender(rtcSender);

// On every epoch installed by the ratchet, push the new chain key into the worker.
await cryptor.setEpoch({
  epoch: ratchet.epoch,
  peerIndexMap: ratchet.currentPeerIndexMap,
  chainKey: ratchet.getEpochChainKey(ratchet.epoch)!,
});
```

The smoke test at [`src/__tests__/sframe.smoke.test.ts`](./src/__tests__/sframe.smoke.test.ts) is the most accurate working example of the AEAD path.

## Architecture

```
encoded media frame
     │
     ▼
┌──────────────┐   transferable buffer    ┌────────────────┐
│  main thread │ ─────────────────────────►│  worker thread │
│              │                           │  ┌──────────┐  │
│  RTC sender  │                           │  │  SFrame  │  │
│  / receiver  │ ◄─────────────────────────│  │  AEAD    │  │
└──────────────┘   encrypted + header      │  └──────────┘  │
                                           │  CryptoKey     │
                                           │  (never leaves)│
                                           └────────────────┘
```

Why a worker. WebCrypto `CryptoKey` objects are not transferable across `postMessage` as raw bytes — only as opaque handles. The ratchet derives the chain key on the main thread (so application code can drive epoch policy) and imports it into a non-extractable `CryptoKey` before posting handles to the worker. The worker performs AEAD on encoded frames in its own realm; if main-thread code is later compromised by a content-script XSS, frame plaintext is not reachable from there. The worker also keeps AEAD off the main thread, which avoids audio/video jitter.

Either `RTCRtpScriptTransform` (preferred, native) or the deprecated `createEncodedStreams` (fallback) is used to thread the encoded-frame stream through the worker. On browsers without either, `FrameCryptor.transitOnly` is set and `attachSender` / `attachReceiver` become no-ops; DTLS still protects transport, but per-sender E2E is not available.

## API surface

The barrel at [`src/index.ts`](./src/index.ts) exports the following public API. Internals (`worker-state`, `worker-frame`, buffer helpers) are not re-exported.

### Top-level classes

| Export | Description |
|--------|-------------|
| `RoomRatchet` | Per-room epoch ratchet. Mint and consume `EpochAnnouncement`s, look up per-sender keys, rotate on membership change. |
| `FrameCryptor` | Main-thread glue between an `RTCRtpSender` / `RTCRtpReceiver` and the worker. |

### SFrame AEAD

| Export | Description |
|--------|-------------|
| `sframeEncrypt(plaintext, key, ctr)` | RFC 9605 AEAD encrypt. Output is `[header][ciphertext+tag]`. |
| `sframeDecrypt(buf, resolveKey, meta?)` | Parse header, resolve key via callback (where you enforce stale-epoch / unknown-sender policy), AEAD-decrypt. |
| `parseHeader(buf)`, `serializeHeader(kid, ctr)` | Header codec — public for callers that need to inspect KID/CTR before delivering a frame. |
| `supportsSFrame()` | Probe for `RTCRtpScriptTransform` / `createEncodedStreams`. |

### Ratchet primitives

| Export | Description |
|--------|-------------|
| `randomChainKey()` | 32 random bytes; the input to per-epoch key derivation. |
| `deriveSenderKeys(chainKey, epoch, peerIndex)` | HKDF a single per-sender `SFrameKey`. |
| `deriveEpochKeyTable(chainKey, epoch, peerIndexMap)` | Derive the full N-peer key table for an epoch. |
| `deriveWrapKey(sharedSecret, epoch)` | HKDF the AES-GCM key used to wrap chain keys for delivery to a peer. |
| `wrapChainKey` / `unwrapChainKey` | AES-GCM wrap/unwrap of a chain key under a wrap key. |
| `generateX25519Keypair()`, `x25519Dh(priv, pub)` | X25519 keypair generation and DH, via WebCrypto with a `@noble/curves` fallback. |

### KID / peer-index helpers

| Export | Description |
|--------|-------------|
| `makeKid`, `joinKid`, `splitKid` | Pack/unpack the 32-bit KID = `(epoch << 16) \| peerIndex`. |
| `newIdentity(peerId)` | Mint an `IdentityKeyPair` (X25519). |
| `buildPeerIndexMap(peerIds)` | Assign 16-bit indices to a sorted member list. |
| `validatePeerIndexMap(map)` | Enforce the no-gap, no-duplicate invariant. |
| `hkdfInfo`, `peerIndexBe16`, `SFRAME_INFO_KEY`, `SFRAME_INFO_SALT` | HKDF input constants and helpers. |

### Types

`EpochAnnouncement`, `EpochKey`, `IdentityKeyPair`, `MemberChange`, `PeerIdentity`, `PeerIndex`, `SFrameError`, `SFrameKey`, `SFrameKeyLookup`, `SFrameKeyResolver`, `SFrameSupport`, `SFrameHeader`, `RoomRatchetOptions`, `FrameCryptorOptions`, `EpochParams`, `PeerIndexMapValidation`.

### Constants

`X25519_KEY_BYTES`, `CHAIN_KEY_BYTES`, `SFRAME_SALT_BYTES`.

### Worker entry point

```ts
new Worker(new URL('sframe-ratchet/worker', import.meta.url), { type: 'module' });
```

## What this does NOT include

- **Key exchange.** Bring your own — MLS, X3DH, simple ECDH-over-signaling, whatever fits your trust model. `sframe-ratchet` consumes `EpochAnnouncement`s; it does not negotiate them.
- **Signaling.** Membership events, epoch announcements, and ICE all travel over your own transport. The package emits structured objects and consumes them; it does not open sockets.
- **WebRTC wiring beyond the transform.** Constructing `RTCPeerConnection`, adding tracks, and SDP munging are the caller's responsibility. Examples of full integration may land in `examples/` later.
- **Framework bindings.** No React/Svelte/Vue wrappers.
- **Identity, authorization, group membership consensus.** The ratchet trusts whatever member list you give it.

## Observability

The worker can emit structured telemetry events to the main thread. Subscribe with `onMetrics`:

```ts
import { onMetrics } from 'sframe-ratchet';

worker.postMessage({ type: 'set-metrics-enabled', enabled: true });

const off = onMetrics(worker, (ev) => {
  // ev.kind: 'encrypt' | 'decrypt' | 'decrypt_fail' | 'ratchet_retry' | 'queue_drop' | 'epoch_advance'
  console.log(ev);
});

// Unsubscribe:
off();
```

Event kinds: `encrypt`, `decrypt`, `decrypt_fail` (carries error `code`), `ratchet_retry` (succeeded/failed), `queue_drop` (`pre_epoch_full` or `stale_epoch`), `epoch_advance`. All handlers are wrapped in `try/catch` — a buggy handler never breaks other listeners. See [ARCHITECTURE.md](./docs/ARCHITECTURE.md#observability) for a full Prometheus-style integration sketch.

## Status

[0.1.0](./CHANGELOG.md) — extracted from a production product and pared down to the parts that are independently useful. Test suite is 38/38 green. API may change before 1.0.

## License

MIT. See [LICENSE](./LICENSE).
