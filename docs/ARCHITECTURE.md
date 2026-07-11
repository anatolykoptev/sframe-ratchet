# Architecture

This document describes how `sframe-ratchet` is structured internally: the frame pipeline, the main/worker split, the ratchet state machine, and a file-by-file map of `src/`.

## Frame pipeline

The encode (send) path:

```
encoded frame (RTCEncoded{Video,Audio}Frame)
        │
        │  WritableStream provided by RTCRtpScriptTransform or createEncodedStreams
        ▼
   ┌──────────────────────────────────────────────────────┐
   │  worker-frame.encodeFrame                            │
   │    1. ratchet lookup: key for current epoch          │
   │    2. allocate sender-wide monotonic CTR             │
   │    3. codec-aware prefix split:                      │
   │         N = getUnencryptedBytes(state.codec, kind)   │
   │         prefix  = plaintext[0..N]  (clear)          │
   │         body    = plaintext[N..]   (encrypted)      │
   │    4. sframeEncrypt(body, key, ctr)                  │
   │         a. serializeHeader(kid, ctr)                 │
   │         b. iv = salt XOR be96(ctr)                   │
   │         c. AES-GCM encrypt body; AAD = header bytes  │
   │    5. replace frame.data with:                       │
   │         [prefix (N bytes)][hdr][ct+tag]              │
   └──────────────────────────────────────────────────────┘
        │
        ▼
   ReadableStream — back to RTCRtpSender
```

Wire format on the network (codec-aware mode, N > 0):

```
┌─────────────────────┬────────────────┬──────────────────────────┬────────────────────────┐
│  unencrypted prefix │  SFrame header │  AES-GCM ciphertext+tag  │  SIF trailer (optional)│
│     (N bytes)       │  (variable)    │  (body length + 16 tag)  │  (T bytes, if enabled) │
└─────────────────────┴────────────────┴──────────────────────────┴────────────────────────┘
 ↑                     ↑                                            ↑
 SFU reads here         SFrame parser starts here (receiver         Present iff `sifTrailer`
 for routing/kind       peels N first)                              is set on the worker.
                                                                    NOT inside AES-GCM AAD.
                                                                    Routing hint only.
```

When no codec is configured (default), N = 0 and the format collapses to `[hdr][ct+tag]` (plus optional trailer) — or the standard SFrame layout `[hdr][ct+tag]` when the SIF trailer is also disabled.

**SIF trailer** (`sifTrailer` field on `WorkerState`, enabled via `set-sif-trailer` control message): an optional fixed-byte suffix appended after the ciphertext+tag. The receiver uses it to detect whether an incoming frame is SFrame-encrypted before attempting AEAD, enabling mixed-room deployments where some participants use E2EE and some do not. When a frame does not end with the configured trailer, the receiver treats it as a plain frame and passes it through unchanged without attempting decryption. The trailer is a routing hint only — see `docs/SECURITY.md` for known limitations.

The decode (receive) path:

```
wire frame from RTCRtpReceiver
        │
        ▼
   ┌──────────────────────────────────────────────────────┐
   │  worker-frame.decodeFrame                            │
   │    1. codec-aware prefix peel:                       │
   │         N = getUnencryptedBytes(state.codec, kind)   │
   │         prefix = wire[0..N]                          │
   │         buf    = wire[N..]  (SFrame header+ct+tag)  │
   │    2. parseHeader(buf) → kid, ctr, bodyOffset        │
   │    3. splitKid(kid) → epoch, peerIndex               │
   │    4. stale-epoch gate:                              │
   │         if epoch < currentMinValidEpoch              │
   │         emit decrypt_failure{stale_epoch}; drop      │
   │    5. tryDecryptWithRatchet(state, buf, epoch, pi)   │
   │         a. try cached key (step 0, or last advanced) │
   │         b. on AEAD fail: derive step 1 via HKDF,    │
   │            try; derive step 2; … up to              │
   │            ratchetWindowSize (default 8)             │
   │         c. on success at step N: advance cached key  │
   │            so next frame at step N hits immediately  │
   │         d. on exhaustion: surface original error     │
   │    6. reassemble: [prefix][plaintext]                │
   │    7. replace frame.data with reassembled bytes      │
   └──────────────────────────────────────────────────────┘
        │
        ▼
   downstream decoder
```

**Receiver side-channel constraint:** both sides must agree on `codec` out-of-band
(e.g. via signalling or `StreamsMsg.codec`). This is the same constraint LiveKit
accepts in their `FrameCryptor` implementation. There is no in-band negotiation
in this library.

Three queueing subtleties live inside the worker state machine:

- **Pre-epoch queue.** Frames may arrive before the first `epoch` message has been processed (the join race). They are parked in `preEpochQueue` and drained when the first epoch installs.
- **pendingDrain flag.** If a second `epoch` message arrives while the first drain is still suspended at an `await`, the early-return on `draining=true` would orphan frames queued for the second epoch. A `pendingDrain` flag re-runs the drain loop once more.
- **Per-frame try/catch.** Frames are processed in a loop; an exception on frame N (e.g. `parseHeader` throwing on a corrupt header) must not abort the loop for frames N+1, N+2, etc. Each frame is wrapped individually.

These three behaviors are covered by tests in `src/__tests__/sframe.smoke.test.ts`.

**Within-epoch ratchet retry window** (`ratchetWindowSize`, default 8): When a sender advances their per-sender key (a forward-secrecy step within an epoch) and in-flight frames encrypted with the OLD key arrive after the receiver expects the new one, AEAD fails. The retry window derives the next step via `deriveNextSenderKey(rawKey, salt, epoch, peerIndex)` — a HKDF-Expand from the current raw key bytes — and retries up to `ratchetWindowSize` times. On success at step N the cached key is advanced so subsequent frames at that step decrypt immediately. On exhaustion the original error is surfaced. Controlled at runtime via the `set-ratchet-window` message. The drain loop (`drainPreEpochQueue`) applies the same retry logic for consistency.

## Cipher suites (RFC 9605 §4.5)

`sframe-ratchet` implements two of the five cipher suites defined in RFC 9605 §4.5, both using AES-GCM and WebCrypto:

| Suite | ID | `CipherSuite` value | AEAD | AEAD key | KDF hash | KDF output (ChainKey) | Tag |
|-------|----|---------------------|------|----------|----------|-----------------------|-----|
| 4 | `0x0004` | `AES_128_GCM_SHA256` | AES-128-GCM | 16 bytes | SHA-256 | 32 bytes | 16 bytes |
| 5 | `0x0005` | `AES_256_GCM_SHA512` | AES-256-GCM | 32 bytes | SHA-512 | 64 bytes | 16 bytes |

Suite 4 is the default and matches the RFC 9605 mandatory baseline. Suite 5 provides AES-256 + SHA-512 for FIPS/HIPAA environments that require 256-bit AES keys.

The suite governs:
- The **HKDF hash** used to derive per-sender AEAD keys and salts from the ChainKey.
- The **AEAD key length** (16 or 32 bytes) imported into WebCrypto for AES-GCM.
- The **ChainKey size** — RFC §4.4.1 defines the base-key size as `KDF.Nh` (SHA-256 → 32 bytes; SHA-512 → 64 bytes).

The suite does **not** govern the X25519 DH key agreement or the AES-GCM chain-key wrap transport (those always use AES-256-GCM + HKDF-SHA-256 as an internal mechanism).

All parties in a room **must** agree on the same suite. The suite is set at construction time on `RoomRatchet`, `FrameCryptor`, and `SimpleKex`, and is carried in the worker `init` message.

**FIPS/HIPAA note:** Suite 5 uses AES-256-GCM (NIST-approved, FIPS 197) and HKDF-SHA-512 (NIST SP 800-56C). Suite 4 uses AES-128-GCM and HKDF-SHA-256, also NIST-approved. All cryptographic operations go through WebCrypto (`crypto.subtle`); FIPS validation status depends on the host platform's WebCrypto implementation.

## Main / worker split

`CryptoKey` is the natural boundary. WebCrypto guarantees that an imported non-extractable key cannot be exported back to raw bytes from JavaScript. By doing the import on the main thread and posting only the resulting handle to the worker, two things hold simultaneously:

- The worker performs AEAD without ever holding raw key material that could leak through a future `postMessage` bug.
- The main thread can drive epoch policy (when to rotate, which peers are members) without needing AEAD primitives — those live entirely in the worker.

The chain key itself does briefly exist as bytes on the main thread (because `deriveEpochKeyTable` runs there). It is wiped from JS reachability when the corresponding `EpochState` is forgotten after the 5-second grace window. The package does not — and in JS cannot — zero memory; this is a residual exposure called out in `SECURITY.md`.

Posting to the worker uses `postMessage` with transferable buffers where applicable. Frame `data` is an `ArrayBuffer` that the transform handoff owns; mutating it in place is the standard pattern for encoded-frame transforms and is what `worker-frame` does.

## Ratchet state machine

`RoomRatchet` maintains `epochs: Map<number, EpochState>` and a `currentEpoch` cursor. Each epoch is in one of four logical states:

```
   pending           active            retiring            forgotten
  ──────────►       ─────────►        ─────────►          ─────────►
  (not yet         (currentEpoch     (currentEpoch       (removed
   installed;       == v; sender      moved past v;       from epochs
   frames go        derives self      receiver still      map; resolver
   to pre-          key from this     decrypts via         returns null;
   epoch queue)     epoch's table)    getReceivingKey;     decodeFrame
                                      5 s grace timer      stale-epoch
                                      pending)             gate fires)
```

Transitions:

- **pending → active:** `installEpoch(version, chainKey, peerIndexMap)` is called, either from `startNewEpoch` (this node authored the epoch) or from `consumeEpochAnnouncement` (this node received a wrapped chain key from the author). If `version > currentEpoch`, `currentEpoch` is bumped and the previous epoch enters `retiring`.
- **active → retiring:** triggered by the bump in `installEpoch`; a `setTimeout` for 5,000 ms is scheduled with `forgetEpoch(prev)`.
- **retiring → forgotten:** the timer fires (or `forgetEpoch` is called explicitly). The `EpochState` is removed from the map; subsequent `getReceivingKey(prev, pi)` returns `null`.

Authorship rule: the peer whose `peerId` is lexicographically smallest across the current member set is the **authoritative author** of new epochs. They mint random chain keys; other peers wait for an `EpochAnnouncement` addressed to them. `rotateOnMemberChange` is a no-op (returns `[]`) on non-author nodes.

The on-wire `EpochAnnouncement` carries the new chain key wrapped under an AES-GCM key derived (via HKDF) from an X25519 DH shared secret between the author's ephemeral key and the recipient's identity key. There is one announcement per recipient — the `peer_index_map` is identical across all of them so every recipient agrees on the per-sender peer-index assignment.

## File-by-file map

`src/` contains 10 files plus tests and an `internal/` directory:

| File | Role |
|------|------|
| `index.ts` | Public API barrel. The single export surface — anything not re-exported here is internal. |
| `types.ts` | Cross-module type contracts (`SFrameKey`, `EpochAnnouncement`, `PeerIdentity`, `SFrameError`, etc.). |
| `sframe.ts` | RFC 9605 AEAD encrypt/decrypt. IV derivation, AES-GCM glue, resolver dispatch. |
| `sframe-header.ts` | Header codec: `parseHeader` / `serializeHeader` over the 32-bit KID + variable-width CTR layout. |
| `ratchet.ts` | `RoomRatchet` class: epoch lifecycle, member changes, announcement mint/consume, 5 s grace wipe. |
| `ratchet-crypto.ts` | Primitives: HKDF chain-key derivation, X25519 DH (WebCrypto + noble fallback), AES-GCM wrap/unwrap. |
| `ratchet-ids.ts` | KID pack/unpack, peer-index map build/validate, HKDF info constants, announcement wrap helper. |
| `frame-cryptor.ts` | `FrameCryptor` class: main-thread glue between an `RTCRtpSender` / `RTCRtpReceiver` and the worker. |
| `worker.ts` | Worker entry point. Wires `onrtctransform` and the `postMessage` fallback to the state machine. |
| `worker-state.ts` | Per-worker state: current epoch, key table, pre-epoch queue, message dispatch. |
| `worker-frame.ts` | Encoded-frame I/O: `encodeFrame`, `decodeFrame`, the read/write stream pipe, drain loop. |
| `worker-types.ts` | Worker `postMessage` contract: `InMsg`, `OutMsg`, `PerSenderKeyBundle`, `Side`, `Codec`, `FrameKind`. |
| `codec-partial.ts` | `getUnencryptedBytes(codec, frameKind) → number`: codec-to-prefix-byte-count table for partial encryption. |
| `sif-trailer.ts` | `DEFAULT_SIF_TRAILER` constant and `getDefaultSifTrailer()` accessor for the SIF trailer feature. |
| `internal/buffer.ts` | `toArrayBuffer` helper to keep WebCrypto happy across SAB-backed and plain `Uint8Array` inputs. |
| `errors.ts` | Typed error class hierarchy — all domain errors extend `SFrameError`. |

## Error handling

All domain errors extend the abstract base `SFrameError` (from `src/errors.ts`), which carries a stable `code` string and a typed `context` object. Callers can branch on error class instead of parsing message strings:

```ts
if (err instanceof StaleEpochError) {
  const { frameEpoch, minValidEpoch } = err.context;
}
```

| Class | Code | Thrown when |
|-------|------|-------------|
| `KeyNotFoundError` | `KEY_NOT_FOUND` | Decrypt path cannot find a key for (epoch, peerIndex) — epoch missing or peer not in key table. |
| `StaleEpochError` | `STALE_EPOCH` | Frame's epoch is below `currentMinValidEpoch` — frame discarded before any AEAD attempt (spec §7.4). |
| `AEADAuthError` | `AEAD_AUTH_FAIL` | AES-GCM tag check failed — key mismatch, corrupt frame, or wrong nonce. |
| `RatchetWindowExhaustedError` | `RATCHET_WINDOW_EXHAUSTED` | Forward ratchet retry window exhausted without a matching key. |
| `HeaderParseError` | `HEADER_PARSE` | SFrame header is malformed — empty buffer, truncated KID/CTR, or KID out of safe-integer range. |
| `QueueFullError` | `QUEUE_FULL` | Pre-epoch ring buffer overflow (oldest frame dropped; this error is available for programmatic detection). |

Programmer-mistake / invariant violations (e.g. calling `startNewEpoch` on a non-author without a `viaChainKey`) remain as generic `Error` or `TypeError`.

## Observability

The worker emits structured telemetry over `postMessage` when metrics are enabled. Consumers subscribe on the main thread via `onMetrics`:

```ts
import { onMetrics } from 'sframe-ratchet';

// Enable emission (off by default — zero cost on hot path).
worker.postMessage({ type: 'set-metrics-enabled', enabled: true });

const off = onMetrics(worker, (ev) => {
  switch (ev.kind) {
    case 'encrypt':   encryptCounter++;  break;
    case 'decrypt':   decryptCounter++;  break;
    case 'decrypt_fail': failCounter++;  break;
    case 'ratchet_retry': retryCounter++; break;
    case 'queue_drop': dropCounter++;    break;
    case 'epoch_advance': /* log */      break;
  }
});

// Stop listening:
off();
```

### Event kinds

| Kind | Payload fields | Fired when |
|------|---------------|------------|
| `encrypt` | `epoch`, `peerIndex`, `bytes`, `codec?` | Successful `encodeFrame` |
| `decrypt` | `epoch`, `peerIndex`, `bytes` | Successful `decodeFrame` |
| `decrypt_fail` | `code`, `epoch?`, `peerIndex?` | AEAD failure, stale epoch, or window exhaustion |
| `ratchet_retry` | `epoch`, `peerIndex`, `steps`, `succeeded` | Within-epoch ratchet retry attempted |
| `queue_drop` | `reason` (`pre_epoch_full` \| `stale_epoch`), `epoch?` | Frame silently dropped |
| `epoch_advance` | `from`, `to` | `currentEpoch` promoted to a higher epoch |

### Wire format

Each event is posted as `{ type: 'metrics'; event: MetricsEvent }`. The `onMetrics` helper filters on `data.type === 'metrics'` and wraps the user handler in a `try/catch` so a buggy handler cannot break subsequent listeners.

### Prometheus-style integration sketch

```ts
const counters = { encrypt: 0, decrypt: 0, decrypt_fail: 0, ratchet_retry: 0, queue_drop: 0 };

onMetrics(worker, (ev) => {
  if (ev.kind in counters) counters[ev.kind as keyof typeof counters]++;
});

// Expose via a /metrics endpoint:
// sframe_encrypt_total, sframe_decrypt_total, sframe_decrypt_fail_total, …
```

## Receiver-epoch detection & recovery

A receiver's worker starts at `currentEpoch = -1` and installs an epoch only when
the main thread calls `FrameCryptor.setEpoch(...)` — which the app does after it
receives and consumes the peer's `EpochAnnouncement`. If that announcement is
never delivered (dropped signaling, a misrouted DataChannel), the worker stays at
`-1` for the whole call: every inbound frame is queued in the bounded pre-epoch
ring (`preEpochQueueCap`, default 50) and, once full, silently dropped. The
main thread has no media, and — before v0.6 — no way to observe or recover it.

Two first-class, always-emitted worker→main signals close that gap (independent
of `metricsEnabled`):

| Signal | Payload | Fired when | Main-thread surface |
|--------|---------|-----------|---------------------|
| `epoch_applied` | `epoch` | `installEpoch` advances `currentEpoch` | `FrameCryptor.getAppliedEpoch()`, `onEpochApplied(epoch)` |
| `decrypt_starved` | `peerIndex?`, `framesDropped`, `sinceMs` | a frame is dropped at pre-epoch overflow (COALESCED, ≤1 per `STARVE_COALESCE_MS` per episode; reset on the next successful decode) | `onDecryptStarved(info)` |

`peerIndex` is the in-payload SFrame-header hint (`splitKid(hdr.kid)` on the
cleartext header) — never an RTP header extension. The signal is a stats-only
liveness hint; key selection and AEAD are unchanged.

Recovery wiring (consumer side):

```ts
const cryptor = new FrameCryptor({
  worker, role: 'receiver', peerId: 'alice', peerIndex,
  onDecryptStarved: ({ peerIndex, framesDropped, sinceMs }) => {
    // No usable epoch installed and frames are being lost — ask the author to
    // re-send the epoch (rewrapCurrentEpochFor) / re-run your key exchange.
    requestEpochRepropagation(peerIndex);
  },
  onEpochApplied: (epoch) => {
    // Recovered: the worker now has an active epoch.
    clearRecoveryTimer();
  },
});

// Or poll: a receiver still at -1 well after media started is stuck.
if (cryptor.getAppliedEpoch() === -1 && Date.now() - callStart > 3000) {
  requestEpochRepropagation();
}
```

`RoomRatchet.getEpochPeerIndexMap(epoch)` returns the `peerIndexMap` for an
installed epoch (defensive copy, or `null` if unknown/wiped) so recovery code can
inspect membership without reaching into `ratchet.epochs` internals.

> The SFrame KID carried in an RTP header extension (oxpulse-sfu-kit #42) could
> let a receiver detect starvation before the payload arrives, but that channel
> is dormant end-to-end today; consuming it is a documented follow-up. Detection
> stays in-payload-only regardless (RFC 9605 §4.4: the receiver selects the key
> from the in-payload SFrame header and lets AEAD fail closed on mismatch).
