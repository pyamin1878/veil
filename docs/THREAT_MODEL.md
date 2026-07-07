# Veil Threat Model

This document is the reference point for security decisions in Veil. Every
change that touches the protocol, the server, or the client's crypto should be
checked against it — and every known gap here must map to a tracked
`security`-labelled issue so it gets closed incrementally, not forgotten.

## What Veil protects

| Asset | Protection |
|---|---|
| Message content | AES-256-GCM, key derived on-device via ECDH(P-256) → HKDF-SHA256. The server relays `{iv, ct}` blobs it cannot decrypt. |
| Message integrity | GCM authentication — any tampering makes decryption fail loudly on the recipient's device. |
| Private keys | Generated non-extractable in WebCrypto; persisted only as a `CryptoKey` in IndexedDB. Not even the app's own JavaScript can read the key bytes. |
| Key authenticity | Safety codes (SHA-256 fingerprints of public keys) compared out-of-band detect a key-substitution MITM. |
| Delivered code | CSP (`default-src 'none'`, no inline scripts, `frame-ancestors 'none'`) limits what a compromised or malicious response could execute; HTTPS (mandatory in production) protects code in transit. |
| Availability | Per-IP rate limits on join/send, a total-user cap, per-user queue caps, body-size caps, and reaping of ghost users bound the server's memory and work. |

## Trust assumptions

- **The server is untrusted for content.** It must never be able to read,
  forge, or undetectably modify a message. This is the core invariant.
- **The server is trusted for availability and metadata.** It sees who is
  online, who talks to whom, when, and roughly how much (ciphertext lengths).
  This is by design and documented to users.
- **The endpoint is trusted.** If a user's device or browser is compromised,
  no messaging app can protect their messages.
- **TLS termination is trusted in hosted deployments** (Render/Cloudflare
  terminate HTTPS in front of the Python process).

## Attacker classes and current posture

### Network attacker (passive or active, no TLS break)
Sees only TLS. With TLS stripped (misconfigured self-hosting over plain HTTP),
message content is still encrypted, but tokens, metadata, and the delivered
JavaScript are exposed — hence the "run behind HTTPS" requirement.

### Malicious or compromised server
Cannot read messages. **Can**: withhold or reorder delivery, observe metadata,
attempt key substitution on first contact (detectable via safety codes), and —
currently — **replay or reflect recorded ciphertexts** (see gaps below).

### Abusive client
Rate-limited per IP (8 joins/min, 30 sends/5s), bounded by `MAX_USERS`,
64 KB body cap, and 512-event queue cap. Public keys must parse as real
uncompressed P-256 points; display names are stripped of non-printable
characters and length-capped. All rendering uses `textContent` (no HTML
injection path).

### Malicious peer
Holds the shared conversation key, so within a 1:1 conversation "forgery" by
the only other participant is meaningless. XSS via message content is blocked
by `textContent` rendering plus CSP.

## Known gaps (each tracked as a `security` issue)

| # | Gap | Impact | Planned fix |
|---|---|---|---|
| 1 | **No sender/sequence binding in ciphertext (replay & reflection).** Nothing cryptographically binds a message to its sender, direction, or position. | The server can re-deliver an old ciphertext, or reflect a message back to its author as if the peer sent it. | Bind sender public key + monotonic sequence number into AES-GCM additional data; recipients reject stale or mis-bound messages. *(Increment 2 — highest priority.)* |
| 2 | **No forward secrecy / post-compromise security.** One static key per conversation pair. | A future device compromise decrypts previously recorded ciphertext. | Ephemeral per-session ECDH keys signed by the identity key; stepping stone to a Double Ratchet. |
| 3 | **Trust-on-first-use, per session.** Keys are re-learned from the server every session; safety codes are the only defence. | A MITM that begins on a later session is indistinguishable from a peer rejoining. | Pin peer keys in IndexedDB and warn loudly when a known peer's key changes. |
| 4 | **Auth token in the SSE query string.** `EventSource` cannot set headers, so the token rides in the URL. | Tokens can leak into proxy/server logs (they are session-scoped and expire with the in-memory session). | Short-lived one-time ticket endpoint: POST for a ticket, open SSE with the ticket. |
| 5 | **Ciphertext length leaks message length.** | Coarse metadata (message sizes, typing patterns). | Pad plaintexts to size buckets before encryption. |

## Out of scope

- Anonymity / traffic analysis resistance (Veil is not Tor)
- Compromised endpoints or browsers
- Server-side message history (there is none — ephemerality is a feature)
- Multi-device identity sync (until the feature exists)
