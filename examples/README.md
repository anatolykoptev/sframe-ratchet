# Examples

| Example | What it shows | Complexity |
|---------|---------------|------------|
| [`01-roundtrip/`](./01-roundtrip/) | Node.js encrypt/decrypt smoke test; `SimpleKex` + `sframeEncrypt` + `sframeDecrypt` | Minimal |
| [`02-mesh-browser/`](./02-mesh-browser/) | Browser split-pane UI; two simulated peers exchange encrypted frames over `MessageChannel` every 500 ms; E2EE toggle | Medium |
| [`03-sfu-integration/`](./03-sfu-integration/) | Architecture guide + code snippets for wiring sframe-ratchet against a real SFU via `RTCRtpScriptTransform`; no runtime | Reference |

## Start here

**New to sframe-ratchet?** Run the Node roundtrip first:

```bash
cd examples/01-roundtrip
npm install
npm start
```

You will see encrypted hex bytes and decrypted plaintext side by side in under
30 seconds.

## For browser development

See `examples/02-mesh-browser/` — a Vite-based page that shows two peers
exchanging SFrame-encrypted frames in real time. Toggle E2EE on/off to compare
plaintext and ciphertext modes.

## For production SFU integration

See `examples/03-sfu-integration/README.md` — architecture diagram, full
`RTCRtpScriptTransform` wiring, epoch rotation, and key delivery guidance.
No SFU SDK bundled; the snippets follow a LiveKit-shaped API that maps
directly to any standards-compliant SFU.
