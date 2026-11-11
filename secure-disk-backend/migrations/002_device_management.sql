-- Secure Disk v0.3: device proof-of-possession, session binding and audit history.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id UUID;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'sessions_device_id_fk') THEN
    ALTER TABLE sessions ADD CONSTRAINT sessions_device_id_fk
      FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE SET NULL;
  END IF;
END $$;
CREATE INDEX IF NOT EXISTS sessions_device_active_idx
  ON sessions(device_id, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS device_auth_challenges (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  session_id UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
  signed_message TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  consumed_at TIMESTAMPTZ,
  failed_attempts SMALLINT NOT NULL DEFAULT 0 CHECK (failed_attempts BETWEEN 0 AND 5),
  CHECK (expires_at > created_at)
);
CREATE INDEX IF NOT EXISTS device_auth_challenges_active_idx
  ON device_auth_challenges(user_id, device_id, expires_at) WHERE consumed_at IS NULL;

CREATE TABLE IF NOT EXISTS device_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE RESTRICT,
  actor_session_id UUID REFERENCES sessions(id) ON DELETE SET NULL,
  event_type TEXT NOT NULL CHECK (event_type IN (
    'registered_pending', 'proof_required', 'proof_verified', 'revoked', 'login_proof_verified'
  )),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS device_events_user_created_idx
  ON device_events(user_id, created_at DESC);

-- Existing v0.2 sessions had no device_id binding. Revoke them so no legacy
-- unbound session can survive a device revocation after the upgrade. Users
-- sign in once with v0.3; the frontend proves its key and binds the new session.
UPDATE sessions
   SET revoked_at=now(), revoke_reason='v0.3_device_binding_required'
 WHERE revoked_at IS NULL;

-- v0.2 devices were activated on public-key submission without proof of
-- possession. Require every existing active device to complete one challenge
-- before it is considered trusted by the v0.3 client.
WITH demoted AS (
  UPDATE devices SET status='pending' WHERE status='active' RETURNING id,user_id
)
INSERT INTO device_events(user_id,device_id,event_type,metadata)
SELECT user_id,id,'proof_required','{"reason":"v0.3_upgrade_requires_key_possession_proof"}'::jsonb
FROM demoted;
