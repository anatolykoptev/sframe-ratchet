# Contributing

## Running tests

```bash
npm install
npm test          # vitest run — 38 unit tests
npm run typecheck # tsc --noEmit
npm run build     # tsup → dist/
```

Node 20 or later required. No native addons; tests run entirely in Node via WebCrypto polyfill provided by Node itself.

## Code style

- TypeScript strict mode. No `any` except at verified external boundaries.
- Immutable patterns: return new objects, do not mutate inputs.
- Functions under 50 lines; files under 400 lines.
- Errors are thrown with descriptive messages; no silent failures on crypto paths.
- No `console.log` in source (test `stdout` is fine).

There is no formatter config yet — match the style of the file you edit.

## What is in scope

- **Test vectors.** Additional known-answer tests for the AEAD and ratchet derivation, especially vectors derived from external reference implementations.
- **Interop reports.** Notes or thin shim layers demonstrating wire compatibility with other SFrame implementations (Medooze, @telnyx/sframe, LiveKit).
- **MLS adapter sketch.** A thin adapter that consumes an MLS epoch secret and feeds it into `RoomRatchet.consumeEpochAnnouncement`.
- **Performance improvements** to the AEAD or ratchet that stay within the RFC 9605 wire format.
- **Bug fixes** with a reproduction test.

## What is out of scope

- Key exchange protocols (MLS, X3DH, etc.) — plug them in at the application layer.
- Signaling transport — no sockets, no DataChannel management.
- Framework bindings (React, Svelte, Vue, etc.) — these belong in separate packages.
- WebRTC wiring beyond the encoded-transform layer.
- SDP munging or ICE.

## Pull requests

- One logical change per PR.
- New behaviour needs a test.
- Crypto-path changes need a rationale comment citing the relevant RFC section or threat model entry in `docs/SECURITY.md`.
- Run `npm test && npm run typecheck && npm run build` before pushing.
