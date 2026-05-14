# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### BREAKING

- **Default cipher suite corrected to RFC 9605 suite 4 (`AES_128_GCM_SHA256`).** The 0.1.0 code path derived 32-byte AEAD keys using SHA-256 HKDF, which matched no defined RFC 9605 suite. The corrected default (suite 4) derives **16-byte AES-128-GCM** keys using SHA-256 HKDF. Frames encrypted with 0.1.0 **cannot be decrypted** with 0.2.0 code. Known internal consumers (e.g. oxpulse-chat) must re-key or pin to 0.1.0 until they upgrade.

### Added

- **Suite 5 (`AES_256_GCM_SHA512`):** AES-256-GCM AEAD with HKDF-SHA-512 and 64-byte ChainKey. Select per room via `suite: 'AES_256_GCM_SHA512'` on `RoomRatchet`, `FrameCryptor`, and `SimpleKex`.
- `CipherSuite` type, `DEFAULT_CIPHER_SUITE` constant, `suiteParams()` helper exported from the public barrel.
- `suite` field on `RoomRatchetOptions`, `FrameCryptorOptions`, `SimpleKexConfig`, and `WorkerState`.
- `SimpleKex` now uses PBKDF2-SHA-512 and HKDF-SHA-512 when `suite: 'AES_256_GCM_SHA512'` is set.
- New test file `src/__tests__/cipher-suite-5.test.ts` (19 tests): suite 5 round-trip, SimpleKex integration, suite isolation, and a locked deterministic regression vector.
- `docs/ARCHITECTURE.md` — "Cipher suites" section with RFC §4.5 table and FIPS/HIPAA framing.
- `docs/SECURITY.md` — "FIPS / HIPAA conformance" section with primitive table, conformance note, and migration guidance.

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

[Unreleased]: https://github.com/anatolykoptev/sframe-ratchet/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/anatolykoptev/sframe-ratchet/releases/tag/v0.1.0
