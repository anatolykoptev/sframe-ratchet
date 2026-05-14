# 01-roundtrip

Minimal Node.js demo: create two SFrame contexts (sender and receiver) using
`SimpleKex` with a shared password, encrypt a plaintext frame, then decrypt it
and assert the round-trip is lossless.

No browser required. Runs in Node 20+ using the built-in WebCrypto API.

## How to run

```bash
cd examples/01-roundtrip
npm install
npm start
```

## Expected output

```
=== sframe-ratchet 01-roundtrip ===

Plaintext : hello, sframe-ratchet!
Ciphertext: 010000...  (hex, ~50 bytes)
Decrypted : hello, sframe-ratchet!

✓ Round-trip OK
```

The ciphertext will be different on every run because SFrame includes a
monotonic counter (CTR) that is fed into the IV. The plaintext and decrypted
strings are always identical.

## What it shows

| Step | API used |
|------|----------|
| Shared key from password | `SimpleKex.initialEpoch()` |
| Per-sender key derivation | `deriveSenderKeys(chainKey, epoch, peerIndex)` |
| RFC 9605 AES-GCM encryption | `sframeEncrypt(plaintext, key, ctr)` |
| RFC 9605 AES-GCM decryption | `sframeDecrypt(ciphertext, keyLookup)` |

## Next steps

- See `examples/02-mesh-browser/` for a browser demo with two peers exchanging
  frames over a `MessageChannel`.
- Replace `SimpleKex` with a real key-exchange protocol (MLS, X3DH) for
  production use. `SimpleKex` has no forward secrecy or revocation.
