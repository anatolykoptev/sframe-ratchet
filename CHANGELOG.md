# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
