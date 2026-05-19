# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] — 2026-05-18

### Added
- `sframe-ratchet/chat` — new subpath export with high-level chat-mode provider for non-WebRTC messaging applications.
  - `createChatProvider(opts)` — single-call factory returning `{ seal, unseal, rotate, dispose }`.
  - **HKDF key derivation**: derives per-`(roomId, senderUid)` AES-128-GCM key + 12-byte salt from a caller-supplied HKDF base-key (usages: `deriveKey, deriveBits`). Salt = SHA-256(roomId) for room-scoped isolation; info strings include full `senderUid` for sender auth.
  - **LRU key cache**: 256-entry per-provider cache (`KeyDerivationCache`); `rotate(roomId)` evicts all room entries.
  - **CTR strategies**: `random-64` (default, 64-bit random, birthday bound ~2^32/sender) and `monotonic-idb` (IDB-backed atomic counter, multi-tab safe via `navigator.locks`, graceful fallback in Node.js).
  - **KID encoding**: `epoch=0` (chat mode reserved), `peerIndex = SHA-256(senderUid)[0:2] & 0xFFFF` via existing `makeKid()`.
  - **Replay protection**: sliding window (default 1024) per `(roomId, senderUid)`; `replayWindow: 0` disables.
  - **`ReplayError`** class extending `SFrameError` with `code = 'REPLAY'`.
  - README section "Chat-mode (non-WebRTC)" with threat-model table.

### Threat model additions (v0.5)
- **Defended**: AEAD confidentiality/integrity, in-session sender auth (via HKDF info), in-session replay, cross-room isolation.
- **Not defended**: forward secrecy, post-compromise security, cross-session replay under `random-64`, traffic analysis.
- **Explicitly documented**: symmetric AEAD — any room member can forge messages from any other member. Sign-then-encrypt is v0.6 roadmap.

### No breaking changes
- v0.4 consumers (WebRTC path) are unaffected — no changes to `sframe-ratchet` main barrel, `/worker`, or `/kex-simple`.
- `getKey` contract change is **additive and subpath-only**: only applies to `sframe-ratchet/chat` consumers. The new contract requires HKDF base-key (usages: `deriveKey, deriveBits`) rather than AES-GCM key. v0.4 code does not import this subpath.

### Dependencies
- `fake-indexeddb` added as devDependency (test-only; not shipped in dist).


## [0.4.0] — 2026-05-14

### Performance
- Bundle minified — dist JS reduced 49% (46 kB → 23 kB), tarball 30.1 → 26.1 kB
- Vitest test pool now parallel (threads, 2-4 workers) — test wall time reduced from ~4.25s to ~1.5s
- Hot-path encode: skip redundant `toArrayBuffer` copies for fresh iv/header buffers, collapse double Uint8Array allocation in `encodeFrame`. Saves ~3 allocations per frame.

### Removed
- Internal HKDF helpers removed from public barrel (semver minor pre-1.0): `hkdfInfo`, `peerIndexBe16`, `SFRAME_INFO_KEY`, `SFRAME_INFO_SALT`, `joinKid`. Available via internal imports if needed.

### Tests
- Shared test fixtures extracted to `src/__tests__/helpers.ts` (makeFrame, makeBundle, makeBundles) — net −100 lines, no behaviour change.
- 264 → 277 tests (+13 from encode-fast-path coverage)

## [0.3.0] — 2026-05-14

### Added
- NIST CAVP test vectors for AES-GCM (SP 800-38D) and HKDF (RFC 5869) — `src/__tests__/cavp.test.ts`
- Constant-time SIF trailer comparison — branchless XOR-OR fold, prevents timing leak on trailer match
- Strict-FIPS mode flag — `enableStrictFips()` rejects AES-128, rejects SimpleKex, enforces non-extractable keys
- `FipsModeViolationError` typed error
- `docs/COMPLIANCE.md` — FIPS 140-3, HIPAA, CNSA alignment map with explicit out-of-scope boundaries
- README "FIPS strict mode" and "Compliance" sections

### Changed
- WebCrypto `importKey` now always uses `extractable: false` via internal helper — structural enforcement, no API surface change
- `docs/SECURITY.md` gains "Side channels" section

### Tests
- 198 → 264 (+66 across CAVP, constant-time, strict-FIPS)

## [0.2.0] — 2026-05-14

### Added

- AES-256-GCM-SHA512 cipher suite (RFC 9605 suite 5) — FIPS / HIPAA aligned. Select via `suite: 'AES_256_GCM_SHA512'` on `RoomRatchet`, `FrameCryptor`, and `SimpleKex`. `CipherSuite` type, `DEFAULT_CIPHER_SUITE` constant, and `suiteParams()` helper exported from the public barrel.
- Codec-aware partial encryption (vp8 key/inter, vp9, h264, av1, opus) — preserves SFU-visible RTP headers and codec syntax while encrypting payload. Configurable per codec via `codecMode` option.
- SIF trailer for mixed E2EE / non-E2EE rooms — optional, off by default. Enables graceful coexistence of encrypted and plaintext senders in the same session.
- Ratchet retry window on decode — smooths over key-rotation desync when a receiver's epoch lags behind the sender. Default window: 8 steps. Configurable via `retryWindow` option.
- Typed error hierarchy — `SFrameError` base with subclasses: `KeyNotFoundError`, `StaleEpochError`, `AEADAuthError`, `RatchetWindowExhaustedError`, `HeaderParseError`, `QueueFullError`. All thrown errors are instanceof-checkable.
- Telemetry hook — `onMetrics(worker, handler)` registers a per-worker callback receiving `encrypt`, `decrypt`, `fail`, `retry`, `drop`, and `epoch` event counters.
- Reference KEX adapter `SimpleKex` — shared-password starter using PBKDF2 + HKDF, intended for demos and development. **NOT for production.**
- RFC 9605 §C test vectors — 47 locked compliance tests covering all defined cipher suites and header formats.
- Examples folder — Node.js round-trip example, browser mesh topology, and SFU integration guide with partial-encryption configuration.

### Changed

- **BREAKING**: Suite 4 now matches RFC 9605 §4.5 exactly (AES-128-GCM + HKDF-SHA-256, 16-byte keys). The 0.1.0 implementation derived 32-byte AES-256 keys with a SHA-256 KDF — matching no defined RFC suite. Frames encrypted with 0.1.0 will **not** decrypt with 0.2.0. Pin to 0.1.0 if you have ciphertext to migrate.

### Test coverage

- 38 → 198 tests across cipher suites, codec partial encryption, SIF trailer, ratchet window, typed errors, telemetry, SimpleKex, and RFC 9605 §C vectors.

## [0.1.0] - 2026-05-13

### Added

- RFC 9605 SFrame AEAD encrypt/decrypt (`sframeEncrypt`, `sframeDecrypt`)
- SFrame wire header codec (`parseHeader`, `serializeHeader`)
- Epoch ratchet with per-sender chain-key derivation, epoch rotation, and 5-second grace window (`RoomRatchet`, `deriveSenderKeys`, `deriveEpochKeyTable`)
- Web Worker pipeline isolating `CryptoKey` objects from the main thread via `RTCRtpScriptTransform` / `createEncodedStreams` (`FrameCryptor`, worker entry point)
- X25519 key agreement via WebCrypto with `@noble/curves` fallback (`generateX25519Keypair`, `x25519Dh`, `newIdentity`)
- AES-GCM chain-key wrap/unwrap for epoch announcement delivery (`wrapChainKey`, `unwrapChainKey`, `deriveWrapKey`)
- KID packing helpers (`makeKid`, `joinKid`, `splitKid`, `buildPeerIndexMap`, `validatePeerIndexMap`)
- 38-test suite covering AEAD, ratchet epoch lifecycle, worker frame queue, and transit-only mode

[Unreleased]: https://github.com/anatolykoptev/sframe-ratchet/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/anatolykoptev/sframe-ratchet/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/anatolykoptev/sframe-ratchet/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/anatolykoptev/sframe-ratchet/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/anatolykoptev/sframe-ratchet/releases/tag/v0.1.0
