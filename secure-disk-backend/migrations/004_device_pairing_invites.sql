-- Secure Disk v0.4.3: trusted-device initiated invitations (Invite-based pairing).
-- QR carries only a short-lived 256-bit capability token; private keys and VMK
-- never leave the client. A claim is bound to an already authenticated,
-- device-proof-verified session belonging to the same account.

CREATE TABLE IF NOT EXISTS device_pairing_invites (
  id UUID PRIMARY KEY,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  initiator_device_id UUID NOT NULL,
  initiator_session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  invite_token_hash BYTEA NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending','claimed','approved','completed','cancelled','expired')),
  claimed_by_device_id UUID,
  claimed_by_device_public_key BYTEA,
  claimed_by_encryption_public_key BYTEA,
  vault_id UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
  encrypted_vmk_blob JSONB,
  approved_by_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  claimed_at TIMESTAMPTZ,
  approved_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  FOREIGN KEY (initiator_device_id,user_id) REFERENCES devices(id,user_id) ON DELETE CASCADE,
  FOREIGN KEY (claimed_by_device_id,user_id) REFERENCES devices(id,user_id) ON DELETE CASCADE,
  CONSTRAINT pairing_invite_token_hash_len CHECK (octet_length(invite_token_hash)=32),
  CONSTRAINT pairing_invite_key_lengths CHECK (
    (claimed_by_device_public_key IS NULL OR octet_length(claimed_by_device_public_key)=32)
    AND (claimed_by_encryption_public_key IS NULL OR octet_length(claimed_by_encryption_public_key)=32)
  ),
  CONSTRAINT pairing_invite_claim_state CHECK (
    (claimed_by_device_id IS NULL AND claimed_by_device_public_key IS NULL
      AND claimed_by_encryption_public_key IS NULL AND claimed_at IS NULL)
    OR
    (claimed_by_device_id IS NOT NULL AND claimed_by_device_public_key IS NOT NULL
      AND claimed_by_encryption_public_key IS NOT NULL AND claimed_at IS NOT NULL)
  ),
  CONSTRAINT pairing_invite_status_claim CHECK (status NOT IN ('claimed','approved','completed') OR claimed_by_device_id IS NOT NULL),
  CONSTRAINT pairing_invite_pending_unclaimed CHECK (status <> 'pending' OR claimed_by_device_id IS NULL),
  CONSTRAINT pairing_invite_status_approval CHECK (status NOT IN ('approved','completed') OR (approved_at IS NOT NULL AND encrypted_vmk_blob IS NOT NULL)),
  CONSTRAINT pairing_invite_approval_state CHECK (
    (approved_at IS NULL AND approved_by_session_id IS NULL AND encrypted_vmk_blob IS NULL)
    OR (approved_at IS NOT NULL AND encrypted_vmk_blob IS NOT NULL)
  ),
  CONSTRAINT pairing_invite_completion_state CHECK ((status='completed') = (completed_at IS NOT NULL)),
  CONSTRAINT pairing_invite_expiry CHECK (expires_at > created_at),
  CONSTRAINT pairing_invite_not_self CHECK (claimed_by_device_id IS NULL OR claimed_by_device_id <> initiator_device_id)
);

-- Only one live invitation per account at a time. Expired rows are transitioned
-- by the create/status/result endpoints before a replacement invitation is made.
CREATE UNIQUE INDEX IF NOT EXISTS device_pairing_invites_one_live_per_user_idx
  ON device_pairing_invites(user_id)
  WHERE status IN ('pending','claimed','approved');
CREATE INDEX IF NOT EXISTS device_pairing_invites_expiry_idx
  ON device_pairing_invites(expires_at) WHERE status IN ('pending','claimed','approved');
CREATE INDEX IF NOT EXISTS device_pairing_invites_initiator_idx
  ON device_pairing_invites(initiator_device_id,created_at DESC);
CREATE INDEX IF NOT EXISTS device_pairing_invites_claimed_device_idx
  ON device_pairing_invites(claimed_by_device_id,created_at DESC)
  WHERE claimed_by_device_id IS NOT NULL;

ALTER TABLE device_events DROP CONSTRAINT IF EXISTS device_events_event_type_check;
ALTER TABLE device_events ADD CONSTRAINT device_events_event_type_check CHECK (event_type IN (
  'registered_pending','proof_required','proof_verified','revoked','login_proof_verified',
  'pairing_requested','pairing_approved','pairing_completed','pairing_cancelled','pairing_expired','vault_initialized',
  'pairing_invite_created','pairing_invite_claimed','pairing_invite_approved','pairing_invite_completed','pairing_invite_cancelled'
));
