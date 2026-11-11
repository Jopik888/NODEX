-- Secure Disk v0.4: VMK device envelopes and QR device pairing.
-- Existing v0.1 vaults/key_envelopes tables are reused; plaintext VMK is never stored.

CREATE TABLE IF NOT EXISTS device_pairing_requests (
  request_id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_device_id UUID NOT NULL,
  target_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  token_hash BYTEA NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','approved','completed','cancelled','expired')),
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  approved_at TIMESTAMPTZ,
  approved_by_device_id UUID,
  approved_by_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  completed_at TIMESTAMPTZ,
  FOREIGN KEY (target_device_id,user_id) REFERENCES devices(id,user_id) ON DELETE CASCADE,
  FOREIGN KEY (approved_by_device_id,user_id) REFERENCES devices(id,user_id) ON DELETE RESTRICT,
  CONSTRAINT pairing_token_hash_len CHECK (octet_length(token_hash)=32),
  CONSTRAINT pairing_request_expiry CHECK (expires_at > created_at),
  CONSTRAINT pairing_approval_state CHECK (
    (approved_at IS NULL AND approved_by_device_id IS NULL)
    OR (approved_at IS NOT NULL AND approved_by_device_id IS NOT NULL)
  ),
  CONSTRAINT pairing_approved_status_check CHECK (status NOT IN ('approved','completed') OR approved_at IS NOT NULL),
  CONSTRAINT pairing_completion_state CHECK ((status='completed') = (completed_at IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS device_pairing_target_active_idx
  ON device_pairing_requests(target_device_id,created_at DESC)
  WHERE status IN ('pending','approved');
CREATE INDEX IF NOT EXISTS device_pairing_user_created_idx
  ON device_pairing_requests(user_id,created_at DESC);

CREATE TABLE IF NOT EXISTS pairing_envelopes (
  request_id UUID PRIMARY KEY REFERENCES device_pairing_requests(request_id) ON DELETE CASCADE,
  source_device_id UUID NOT NULL,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  format_id TEXT NOT NULL CHECK (format_id='vault-device-envelope-v1'),
  format_version INTEGER NOT NULL CHECK (format_version=1),
  ephemeral_public_key BYTEA NOT NULL,
  salt BYTEA NOT NULL,
  nonce BYTEA NOT NULL,
  ciphertext BYTEA NOT NULL,
  envelope_sha256 BYTEA NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  FOREIGN KEY (source_device_id,user_id) REFERENCES devices(id,user_id) ON DELETE RESTRICT,
  CONSTRAINT pairing_ephemeral_key_len CHECK (octet_length(ephemeral_public_key)=32),
  CONSTRAINT pairing_salt_len CHECK (octet_length(salt)=16),
  CONSTRAINT pairing_nonce_len CHECK (octet_length(nonce)=12),
  CONSTRAINT pairing_ciphertext_len CHECK (octet_length(ciphertext)=48),
  CONSTRAINT pairing_envelope_hash_len CHECK (octet_length(envelope_sha256)=32)
);

ALTER TABLE device_events DROP CONSTRAINT IF EXISTS device_events_event_type_check;
ALTER TABLE device_events ADD CONSTRAINT device_events_event_type_check CHECK (event_type IN (
  'registered_pending','proof_required','proof_verified','revoked','login_proof_verified',
  'pairing_requested','pairing_approved','pairing_completed','pairing_cancelled','pairing_expired','vault_initialized'
));

-- Do not change v0.1/v0.2 migrations. The migration runner records this file's checksum.
