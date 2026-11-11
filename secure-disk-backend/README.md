# Secure Disk Backend v0.4

Node.js 22+ / Express 5 / PostgreSQL Control Plane for Secure Disk. v0.4 adds client-side VMK envelopes and authenticated device pairing. It does not store user file contents and does not replace IPFS/Trystero.

## New endpoints

- `GET /api/v1/vault/envelope` — returns only the caller device's encrypted VMK envelope (or an uninitialized/unpaired state).
- `POST /api/v1/vault/initialize` — creates the Vault once, accepting a device-signed envelope for the first trusted device.
- `POST /api/v1/devices/pairing/start` — creates a 10-minute one-time pairing request for the current active device.
- `GET /api/v1/devices/pairing/:requestId` — target session polls its request; trusted source session supplies `X-Pairing-Token` to retrieve target public keys.
- `POST /api/v1/devices/pairing/:requestId/approve` — trusted source device uploads opaque VMK envelope and signs approval digest.
- `POST /api/v1/devices/pairing/:requestId/complete` — target submits a device-signed completion assertion after local decryption; the backend verifies device identity but cannot independently inspect VMK plaintext.
- `POST /api/v1/devices/pairing/:requestId/cancel` — target cancels its own live request.

Mutation routes require the normal session-bound CSRF token. Pairing reads/writes use `Cache-Control: no-store`; the one-time token is sent in `X-Pairing-Token`, not URL/query strings.

## Database update

`npm run db:migrate` applies `003_vault_vmk_pairing.sql` after the previous schema. Do not change already-applied migrations. Take a database backup before upgrade.

## Security notes

The backend validates device signatures and lifecycle state, but cannot inspect the semantic correctness of the encrypted VMK. Client-side pairing encrypts the VMK to the target X25519 public key; target client decrypts it and submits a signed completion assertion. This signature is not a server-verifiable zero-knowledge proof of plaintext decryption. The server stores only opaque envelope bytes. The PIN does not encrypt VMK. There is no Recovery Phrase in v0.4; do not revoke the last Vault-access device until another active device is paired or recovery support has been deployed.

See the top-level `README-v0.4.md` and `README-УСТАНОВКА.md` for the full security model and client flow.
