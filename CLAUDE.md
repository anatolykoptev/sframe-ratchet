# CLAUDE.md

Notes for coding agents working in sframe-ratchet: a TypeScript library for group end-to-end
encryption of browser WebRTC media: RFC 9605 SFrame AEAD, an epoch ratchet, and a Web Worker
pipeline that keeps `CryptoKey` material off the main thread. It is published to npm. Every
document is indexed in [docs/INDEX.md](docs/INDEX.md).

## Layout

- `src/` is the core (header codec, AEAD, `RoomRatchet`, `FrameCryptor`, worker). `src/chat/` is
  the chat-mode provider, `src/mls/` the MLS adapter, `src/internal/` shared helpers. The file map
  is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
- `src/index.ts` is the public barrel: anything not re-exported there is internal. Sub-paths
  (`./worker`, `./kex-simple`, `./chat`, `./chat/mls`, `./mls`) are the `exports` map in
  `package.json` and the entries in `tsup.config.ts`; keep the two in step.
- `src/__tests__/` holds unit, known-answer (RFC 9605 vectors, `cavp.test.ts`), fuzz and
  property tests. `examples/` are runnable demos.
- `@noble/curves`, `@noble/hashes` and (optionally) `ts-mls` are peer dependencies.

## Gate

CI (`.github/workflows/ci.yml`) runs, on Node 20, 22 and 24:

```sh
npm ci
npm run typecheck
npm test
npm run build
```

plus a separate job `npm run mutation` (Stryker, Node 22). `fuzz-nightly.yml` runs the two fuzz
tests every night. A docs-only PR (Markdown, `docs/`, licence, issue and PR templates) skips the
CI jobs through the `docs-scope` job in `ci.yml`; that block is canonical across the fleet and
compared byte for byte, so do not edit it here.

## Invariants that are easy to break

- **Wire format and key schedule are contracts.** The header layout, IV derivation, HKDF `info`
  strings and the RFC 9605 vectors in `sframe.vectors.test.ts` must keep passing; a change there
  breaks interop with every deployed peer. Crypto-path changes need a rationale comment citing the
  RFC section or the threat-model entry in [docs/SECURITY.md](docs/SECURITY.md).
- **Keys are non-extractable `CryptoKey`s** and secret bytes are wiped when an epoch is forgotten
  (5 s after rotation). Never log or serialise key material; never add an extractable path.
- **Decrypt fails closed.** Stale epochs are discarded before any AEAD attempt, an unknown key is a
  typed error, and replay checks run before decrypt and are recorded only after success. Do not
  turn an error into a silent drop or a plaintext fallback.
- **`SimpleKex` is a demo.** It must stay out of production paths and must keep throwing under
  `enableStrictFips()`; strict mode is off by default and must stay so.
- **No transport dependencies.** No sockets, signalling or framework bindings (see
  `CONTRIBUTING.md` for scope).
- **Constant-time comparisons** go through `src/internal/constant-time.ts`.
- **Versions come from release-please** (Conventional Commits). Never tag, or edit the version,
  `CHANGELOG.md` or `.release-please-manifest.json` by hand. `prepare` runs the build on install.
- **`.gitleaksignore` lists the RFC test-vector key material** as known false positives; keep new
  vectors out of any other file shape that would need another ignore.
- **This repository is public.** No hostnames, operator paths, account names, tokens or personal
  data in any tracked file, tests and fixtures included.
