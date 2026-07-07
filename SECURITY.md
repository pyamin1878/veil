# Security Policy

Security is the top priority for this project. Veil is deliberately small and
auditable — if you find a way to break its guarantees, we want to know.

## Reporting a vulnerability

Please report vulnerabilities **privately** — do not open a public issue for
anything exploitable:

1. **Preferred:** GitHub private vulnerability reporting —
   [Security → Report a vulnerability](https://github.com/pyamin1878/veil/security/advisories/new).
2. **Fallback:** email `patrickyamin@gmail.com` with subject `Veil security`.

You should receive an acknowledgement within a few days. Once a fix ships,
you're welcome to disclose publicly (and will be credited unless you prefer
otherwise).

## Scope

In scope — anything that breaks a promise the app makes:

- Message confidentiality or integrity (crypto design or implementation flaws
  in `client/crypto.js`)
- Cross-site scripting or CSP bypasses in the client
- Authentication bypass, or one user acting as another, in `server.py`
- Denial of service that survives the server's rate limits and caps

Known, **documented** limitations are not vulnerabilities — see
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the current list (e.g. no
forward secrecy, trust-on-first-use key distribution, metadata visibility).
Each known gap is tracked as a `security`-labelled issue with its planned fix.

## Supported versions

Only the `main` branch and the hosted instance (https://veil-qayu.onrender.com)
are supported. There are no release branches yet.
