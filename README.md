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

### FIPS strict mode

For regulated deployments that must prevent any weaker configuration from being used at runtime, enable strict mode at application startup:

```ts
import { enableStrictFips } from 'sframe-ratchet';

// Call once, as early as possible (before any RoomRatchet / FrameCryptor construction).
enableStrictFips();
// From this point on:
//   • AES_128_GCM_SHA256 (suite 4) → throws FipsModeViolationError
//   • SimpleKex construction        → throws FipsModeViolationError (no compromise recovery)
//   • WebCrypto importKey           → always non-extractable (enforced by implementation)
```

Strict mode is **off by default** — no breaking change for existing users.

Individual checks can be relaxed:

```ts
enableStrictFips({ requireSuite5: false });   // allow suite 4, still forbid SimpleKex
enableStrictFips({ forbidSimpleKex: false }); // forbid suite 4, allow SimpleKex
```

To restore permissive behaviour at any time:

```ts
import { disableStrictFips } from 'sframe-ratchet';
disableStrictFips();
```

`FipsModeViolationError` extends `SFrameError` with `.code === 'FIPS_VIOLATION'`.

See [`docs/COMPLIANCE.md`](./docs/COMPLIANCE.md) for the full compliance posture and attestation template.

## Install

```bash
npm install sframe-ratchet @noble/curves @noble/hashes
```

`@noble/curves` and `@noble/hashes` are peer dependencies — declared explicitly so you control their version.

## Quick start

Want to run a complete working demo right now? See `examples/01-roundtrip/` for a 30-second Node script, or `examples/02-mesh-browser/` for an in-browser demo.

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

### Detecting and recovering a stuck receiver

A receiver's worker sits at `currentEpoch = -1` until `setEpoch` installs the first
epoch — which only happens after the app receives the peer's `EpochAnnouncement`. If
that announcement is never delivered, the worker drops every inbound frame into its
bounded pre-epoch queue with no media and (before v0.6) no way to observe it. The
`FrameCryptor` now surfaces two always-on signals so the app can detect and recover:

```ts
const cryptor = new FrameCryptor({
  worker, role: 'receiver', peerId: 'alice', peerIndex,
  // Fires (coalesced) while inbound frames are being dropped for lack of an epoch.
  onDecryptStarved: ({ peerIndex, framesDropped, sinceMs }) => {
    requestEpochRepropagation(peerIndex);   // re-run KEX / ask the author to re-send
  },
  // Fires when the worker installs/activates an epoch — i.e. recovery succeeded.
  onEpochApplied: (epoch) => clearRecoveryTimer(),
});

// Or poll: still at -1 well after media started ⇒ stuck.
if (cryptor.getAppliedEpoch() === -1 && Date.now() - callStart > 3000) {
  requestEpochRepropagation();
}
```

`RoomRatchet.getEpochPeerIndexMap(epoch)` returns an installed epoch's `peerIndexMap`
(defensive copy, or `null` if unknown) so recovery code can inspect membership without
reaching into ratchet internals. The signals expose epoch **numbers** and drop
**stats** only — never key material — and detection is in-payload-only (the `peerIndex`
hint comes from the cleartext SFrame header, not an RTP header extension).

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
| `RoomRatchet` | Per-room epoch ratchet. Mint and consume `EpochAnnouncement`s, look up per-sender keys, rotate on membership change, read an epoch's `peerIndexMap` (`getEpochPeerIndexMap`). |
| `FrameCryptor` | Main-thread glue between an `RTCRtpSender` / `RTCRtpReceiver` and the worker. `getAppliedEpoch()` + the `onEpochApplied` / `onDecryptStarved` options expose receiver-epoch detection & recovery. |

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

`EpochAnnouncement`, `EpochKey`, `IdentityKeyPair`, `MemberChange`, `PeerIdentity`, `PeerIndex`, `SFrameError`, `SFrameKey`, `SFrameKeyLookup`, `SFrameKeyResolver`, `SFrameSupport`, `SFrameHeader`, `RoomRatchetOptions`, `FrameCryptorOptions`, `EpochParams`, `DecryptStarvedInfo`, `PeerIndexMapValidation`.

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

## Compliance

`sframe-ratchet` uses only NIST-approved primitives (AES-GCM, HKDF-SHA-2, X25519), wraps WebCrypto to enforce non-extractable keys, and provides an `enableStrictFips()` runtime guardrail that forces suite 5 (AES-256-GCM + HKDF-SHA-512) and rejects the demo KEX. The library is not, and as a JavaScript module cannot be, a FIPS 140-3 validated cryptographic module — validation status depends on the host runtime's WebCrypto provider. See [`docs/COMPLIANCE.md`](./docs/COMPLIANCE.md) for the full mapping to FIPS 140-3, HIPAA Security Rule, CNSA 2.0, and side-channel posture.

## License

MIT. See [LICENSE](./LICENSE).

---

## Chat-mode (non-WebRTC)

`sframe-ratchet/chat` is a high-level subpath export for text/binary messaging applications that don't use WebRTC tracks. Import it without touching the main barrel:

```ts
import { createChatProvider } from 'sframe-ratchet/chat';
```

### Quick start

```ts
// 1. Import a 32-byte shared secret as an HKDF base-key.
//    In production, derive this out-of-band (X25519, MLS, etc.).
const sharedSecret = new Uint8Array(32); // replace with real bytes
const baseKey = await crypto.subtle.importKey(
  'raw', sharedSecret, 'HKDF', false, ['deriveKey', 'deriveBits']
);

// 2. Create a provider (one per user session).
const provider = createChatProvider({
  getKey: async (roomId) => baseKey, // called once per (room, sender) pair, then cached
});

// 3. Seal a message.
const plaintext = new TextEncoder().encode('hello!');
const sealed = await provider.seal(plaintext, { roomId: 'room-abc', senderUid: 'alice' });

// 4. Unseal (on the recipient side, with the same base key).
const recovered = await provider.unseal(sealed, { roomId: 'room-abc', senderUid: 'alice' });

// 5. Rotate on key change (clears derived-key cache + replay state for the room).
provider.rotate('room-abc');
```

### CTR strategies

| Strategy | Description | When to use |
|---|---|---|
| `random-64` (default) | 64-bit random CTR per frame; stateless | Most apps; no IDB dependency |
| `monotonic-idb` | IDB-backed atomic counter; multi-tab safe via `navigator.locks` | When cross-session replay is a concern |

```ts
// monotonic-idb requires a keyspace string to namespace the IDB store:
const provider = createChatProvider({
  getKey: async (roomId) => baseKey,
  ctrStrategy: 'monotonic-idb',
  ctrKeyspace: 'my-app-v1',
});
```

### Options

| Option | Type | Default | Description |
|---|---|---|---|
| `getKey` | `(roomId) => Promise<CryptoKey>` | — | Required. Returns HKDF base-key with `['deriveKey','deriveBits']` usages. |
| `ctrStrategy` | `'random-64' \| 'monotonic-idb'` | `'random-64'` | CTR allocation strategy. |
| `ctrKeyspace` | `string` | — | Required when `ctrStrategy='monotonic-idb'`. |
| `replayWindow` | `number` | `1024` | Recent CTR set size per sender per room. `0` disables replay protection. |
| `onKeyRotated` | `(roomId: string) => void` | — | Called synchronously on `rotate(roomId)`. |

### Threat model

| Property | Status | Notes |
|---|---|---|
| Message confidentiality | Defended | AES-128-GCM AEAD over plaintext |
| Message integrity | Defended | GCM authentication tag covers header + plaintext |
| In-session sender auth | Defended | HKDF `info` contains full `senderUid`; key mismatch → AEAD fail |
| In-session replay | Defended | Sliding window of 1024 CTRs per sender (default) |
| Cross-room key reuse | Defended | HKDF salt = SHA-256(roomId); different rooms → different derived keys |
| Forward secrecy | **Not defended** | One base key per room; compromise exposes history. Mitigate: rotate `getKey` periodically via SDK. |
| Post-compromise security | **Not defended** | No MLS/double-ratchet in v0.5 |
| Cross-session replay | **Not defended** (random-64) | Page reload clears in-memory replay set. Use `monotonic-idb` to persist state. |
| Traffic analysis | **Not defended** | Message size/timing visible to transport |
| **Sender deniability** | **Not defended — document loudly** | Symmetric AEAD: any room member holding the same base key can forge messages from any other member. Sign-then-encrypt is slated for v0.6. |

### No sign-then-encrypt in v0.5

v0.5 uses symmetric AEAD only. Any party that holds the room base key can forge a message attributed to any other sender. This is intentional in v0.5 to keep the audit surface small (+64 B overhead per frame and additional key management complexity for sign-then-encrypt). Non-repudiation / deniability guarantees are a v0.6 roadmap item.
