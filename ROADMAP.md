# Roadmap

Ideas surfaced from a cross-language survey of SFrame implementations (LiveKit, Jitsi, cisco/sframe, sframe-rs, Medooze, shiguredo/sora-e2ee). Full recon with path:line citations: `~/deploy/krolik-server/reports/sframe-ratchet/code-research/competitor-recon-2026-07-18.md`.

## Near-term

### Anti-replay sliding window for media frames — S — #10 (security gap)
Wire the existing `SlidingReplayWindow` (`src/chat/replay.ts`) into the media frame decode path (`worker-frame.ts` / `worker-state.ts`), per-`(epoch, peerIndex)`. `check()` before AEAD, `accept()` after success. RFC 9605 §9.3 (Anti-Replay). Pattern from `sframe-rs:src/frame/validation/replay_attack_protection.rs:11`. Today an attacker can replay a captured encrypted frame and the receiver will decrypt and display it — AEAD authenticates but cannot distinguish fresh from replayed.

### RFC 9605 §10 test vectors — S — #13
Add `src/__tests__/sframe.vectors.test.ts` with golden data from RFC 9605 §10 (also available in `cisco/sframe:scripts/known-answer-test.go:172`). Covers inline KID, extended KID, CTR=0 and CTR>255 edge cases, both cipher suites (4 + 5). Public claim of RFC compliance and a hard guard against regressions in `sframe-header.ts` and `sframe.ts`.

### SAS key verification — M — #11 (security gap)
Derive emoji + decimal SAS from the X25519 shared secret (`HKDF(sha256, dh, "sframe-ratchet-sas-v1")`) so users can compare out-of-band and detect MITM on the ChainKey wrap. No wire-format change. Pattern from `jitsi/lib-jitsi-meet:modules/e2ee/SAS.ts:101` + `OlmAdapter.js:67` (borrowed from Matrix JS SDK). Today a compromised signaling channel can substitute identity keys and MITM the ECIES wrap — AEAD cannot detect this.

### Codec-aware partial encryption — S
Leave the first N bytes of payload unencrypted depending on codec:

| Codec | Unencrypted prefix |
|---|---|
| VP8 keyframe | 10 bytes |
| VP8 interframe | 3 bytes |
| H264 | 1 byte |
| VP9 / AV1 | 0 bytes |
| Opus | 1 byte |

Lets SFUs route by frame type without seeing payload; gives browser decoders "graceful garbage" on key mismatch instead of fatal parse errors. The `TODO(#group-calls-vp8)` in `worker-frame.ts` already marks this. Pattern from `livekit/client-sdk-js` `FrameCryptor.ts:getUnencryptedBytes`.

### ~~SIF trailer for mixed-room support~~ — DONE
Optional fixed suffix on ciphertext that lets a receiver detect "this frame is SFrame-encrypted" before attempting decrypt. Solves the mixed-room case where some peers run E2EE and some do not. Wire-format change — gated behind `sifTrailer` field (default `undefined` = disabled). Pattern from LiveKit. Shipped in `src/sif-trailer.ts`; control message `set-sif-trailer`; 14 tests.

### ~~Ratchet retry window on decode~~ — DONE
On `decrypt_failed` for a known epoch, try ratcheting the key forward up to `ratchetWindowSize` steps (default 8) before giving up. Smooths over RTP/epoch desync during rotation. Distinct from our existing `preEpochQueue` (which handles "no epoch yet") and from epoch rotation itself. Pattern from LiveKit `ParticipantKeyHandler`. Shipped in `src/worker-frame.ts` (`tryDecryptWithRatchet`); control message `set-ratchet-window`; 8 tests in `src/__tests__/ratchet-window.test.ts`.

## Medium-term

### MLS Key ID format (RFC 9605 §5.2) — M — #12
Add `MlsKid` codec alongside the fixed 32-bit KID split (`src/ratchet-ids.ts`), gated behind `kidFormat: 'fixed' | 'mls'` (default `'fixed'`, backward compatible). Layout `[Context ID | Index | Epoch]` with configurable bit widths. Prerequisite for the MLS adapter — an external MLS provider produces §5.2 KIDs which we currently cannot parse. Pattern from `sframe-rs:src/mls/mls_key_id.rs:61`.

### MLS adapter — L
Add a `RoomRatchetProvider` seam in `types.ts` so an external KEX can deliver epoch material. Ship `sframe-ratchet/mls` as an optional sub-package wrapping `mls-rs` (WASM) or `openmls` once the latter has a stable browser target. Pattern from `sframe-rs/src/mls/` `MlsExporter` trait. **Blocked on #12** (MLS Key ID format).

### Decryption-failure-driven key invalidation — S — #14
After N consecutive `AEADAuthError`s for the same `(epoch, peerIndex)`, mark the key invalid and drop subsequent frames without attempting AEAD. Configurable `failureTolerance` (default `-1` = unlimited, preserves current behavior). New `key_invalidated` metric event. Pattern from `livekit/client-sdk-js:ParticipantKeyHandler.ts:58` (`failureTolerance`, `decryptionFailureCounts`).

### Concurrent ratchet dedup — S — #15
`ratchetPromises: Map<string, Promise>` in `worker-state.ts` keyed by `${epoch}:${peerIndex}`. Reuse in-flight ratchet derivation instead of starting a second one on burst decrypt failures. Pattern from `livekit/client-sdk-js:ParticipantKeyHandler.ts:26` (`ratchetPromiseMap`).

### Fuzzing harness — S — #16
Fuzz `parseHeader` (`src/sframe-header.ts`) and `sframeDecrypt` (`src/sframe.ts`) with arbitrary bytes — must never throw uncaught, must fail closed. `fast-check` property tests in vitest (lighter) or `jazzer`/`jsfuzz` standalone target. Nightly CI job, not preflight. Pattern from `cisco/sframe:fuzz/` (`LLVMFuzzerTestOneInput`).

## Explicitly out of scope

- **JFrame trailer** (Jitsi). Predates RFC 9605, breaks interop with standard SFrame.
- **Shared-password mode** (LiveKit). Server learns the key — weaker security posture than our per-recipient ECIES wrap.
- **SSRC/timestamp-derived IV** (Jitsi). RFC §4.4.4 (`salt XOR ctr`) is correct and does not depend on potentially-spoofed RTP metadata.
- **Signal-style double ratchet**. O(N²) channels per group; our epoch + ChainKey + per-sender HKDF is the right shape for groups.
- **WASM AES-GCM**. WebCrypto already uses AES-NI; WASM adds JS↔WASM boundary cost and copies.

## What this library does that others do not

1. Per-sender AEAD keys derived from a shared ChainKey via HKDF (`ratchet-crypto.ts:134`).
2. X25519 ephemeral ECIES wrap for ChainKey delivery — forward secrecy by default.
3. Stale-epoch gate before decrypt (timing-oracle resistant).
4. Bounded pre-epoch ring buffer with re-entrancy guard.
5. Fixed 32-bit KID for predictable header size.
