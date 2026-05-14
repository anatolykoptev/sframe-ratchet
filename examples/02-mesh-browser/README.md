# 02-mesh-browser

Browser demo: two simulated peers (Peer A and Peer B) exchange SFrame-encrypted
frames over a `MessageChannel`. Peer A encrypts a random frame every 500 ms;
Peer B decrypts and displays the result in real time.

No server required — `vite` serves a single HTML page.

## How to run

```bash
cd examples/02-mesh-browser
npm install
npm start
# open http://localhost:5173
```

## What you will see

- Left pane (Peer A): each row shows a sent frame as truncated hex and the
  original plaintext.
- Right pane (Peer B): the received ciphertext hex and the successfully
  decrypted plaintext.
- **Toggle E2EE on/off** to compare encrypted vs. passthrough mode. When E2EE
  is off the raw plaintext bytes cross the channel without any wrapping.

## What it shows

| Concept | Where |
|---------|-------|
| Shared key from password | `SimpleKex.initialEpoch()` |
| Per-sender key derivation | `deriveSenderKeys(ck, epoch, peerIndex)` |
| RFC 9605 encrypt | `sframeEncrypt(plaintext, key, ctr)` |
| RFC 9605 decrypt | `sframeDecrypt(bytes, keyLookup)` |
| Mixed-mode passthrough | SIF trailer toggle (button in UI) |
| Cross-peer message transport | `MessageChannel` (simulates RTCDataChannel) |

## Notes

- `SimpleKex` is a demo-only KEX adapter. It has no forward secrecy,
  membership consensus, or revocation. Production deployments must replace it
  with MLS, X3DH, or another real group-key-agreement protocol.
- The UI wires only the A → B direction for clarity. A full mesh would add a
  symmetric B → A channel.
- The library code runs on the main thread here for simplicity. In production
  use the `sframe-ratchet/worker` entry point with `RTCRtpScriptTransform` so
  `CryptoKey` material never touches the main thread.

## Next steps

- See `examples/03-sfu-integration/README.md` for how to wire sframe-ratchet
  into a real SFU with `RTCRtpScriptTransform`.
