# Roadmap

Ideas surfaced from a cross-language survey of SFrame implementations (LiveKit, Jitsi, cisco/sframe, sframe-rs, Medooze).

## Near-term

### RFC 9605 §10 test vectors — S
Add `src/__tests__/sframe.vectors.test.ts` with golden data from RFC 9605 §10 (also available in `cisco/sframe/test/`). Covers inline KID, extended KID, CTR=0 and CTR>255 edge cases. Public claim of RFC compliance and a hard guard against regressions in `sframe-header.ts` and `sframe.ts`.

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

### MLS adapter — L
Add a `RoomRatchetProvider` seam in `types.ts` so an external KEX can deliver epoch material. Ship `sframe-ratchet/mls` as an optional sub-package wrapping `mls-rs` (WASM) or `openmls` once the latter has a stable browser target. Pattern from `sframe-rs/src/mls/` `MlsExporter` trait.

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
