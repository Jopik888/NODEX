-- Secure Disk Backend v0.1 — initial PostgreSQL migration
-- Based on the reviewed P2P Storage Platform schema.
-- Keep this file immutable after it has been applied; create 002_*.sql for changes.
-- The migration runner wraps this file in a transaction.

-- P2P Storage Platform — PostgreSQL v1 initial schema
-- PostgreSQL 15+ recommended.
-- This is a schema baseline, not an instruction to run against the existing app database.
-- Review migration strategy/backups before applying to any non-empty database.

-- -----------------------------------------------------------------------------
-- Accounts and authentication
-- -----------------------------------------------------------------------------

CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL,
    email_normalized    TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,
    display_name        TEXT,
    status              TEXT NOT NULL DEFAULT 'pending_verification'
                        CHECK (status IN ('pending_verification', 'active', 'locked', 'disabled')),
    email_verified_at   TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at       TIMESTAMPTZ,
    CONSTRAINT users_email_normalized_lower CHECK (email_normalized = lower(email_normalized)),
    CONSTRAINT users_verified_status_consistency CHECK (
        status <> 'active' OR email_verified_at IS NOT NULL
    )
);

CREATE TABLE email_verification_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      BYTEA NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    CONSTRAINT email_verification_token_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT email_verification_expiry CHECK (expires_at > created_at)
);
CREATE INDEX email_verification_tokens_user_idx ON email_verification_tokens(user_id);

CREATE TABLE password_reset_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash      BYTEA NOT NULL UNIQUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL,
    consumed_at     TIMESTAMPTZ,
    CONSTRAINT password_reset_token_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT password_reset_expiry CHECK (expires_at > created_at)
);
CREATE INDEX password_reset_tokens_user_idx ON password_reset_tokens(user_id);

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id           UUID NOT NULL DEFAULT gen_random_uuid(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at        TIMESTAMPTZ,
    -- Opaque access token: SHA-256 digest only, never the raw cookie value.
    access_token_hash   BYTEA NOT NULL UNIQUE,
    access_expires_at   TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ,
    revoke_reason       TEXT,
    user_agent          TEXT,
    ip_address          INET,
    csrf_token_hash     BYTEA,
    CONSTRAINT sessions_csrf_hash_len CHECK (
        csrf_token_hash IS NULL OR octet_length(csrf_token_hash) = 32
    ),
    CONSTRAINT sessions_access_hash_len CHECK (octet_length(access_token_hash) = 32),
    CONSTRAINT sessions_access_expiry CHECK (access_expires_at > created_at),
    CONSTRAINT sessions_expiry CHECK (expires_at > created_at)
);
CREATE INDEX sessions_user_active_idx ON sessions(user_id, expires_at) WHERE revoked_at IS NULL;
CREATE INDEX sessions_family_idx ON sessions(family_id);
CREATE INDEX sessions_access_expiry_idx ON sessions(access_expires_at) WHERE revoked_at IS NULL;

-- Refresh tokens are opaque random values. Only SHA-256 hashes are stored.
-- Keeping token history allows detection of refresh-token reuse after rotation.
CREATE TABLE session_refresh_tokens (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id          UUID NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    token_hash          BYTEA NOT NULL UNIQUE,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    used_at             TIMESTAMPTZ,
    revoked_at          TIMESTAMPTZ,
    replaced_by_id      UUID REFERENCES session_refresh_tokens(id),
    CONSTRAINT refresh_token_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT refresh_token_expiry CHECK (expires_at > issued_at)
);
CREATE INDEX session_refresh_tokens_session_idx ON session_refresh_tokens(session_id);

CREATE TABLE login_challenges (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    challenge_token_hash BYTEA NOT NULL UNIQUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    consumed_at         TIMESTAMPTZ,
    failed_attempts     SMALLINT NOT NULL DEFAULT 0 CHECK (failed_attempts >= 0),
    ip_address          INET,
    CONSTRAINT login_challenge_hash_len CHECK (octet_length(challenge_token_hash) = 32),
    CONSTRAINT login_challenge_expiry CHECK (expires_at > created_at)
);
CREATE INDEX login_challenges_user_active_idx ON login_challenges(user_id, expires_at)
    WHERE consumed_at IS NULL;

CREATE TABLE totp_credentials (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    secret_ciphertext       BYTEA NOT NULL,
    encryption_key_version  TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    confirmed_at            TIMESTAMPTZ,
    disabled_at             TIMESTAMPTZ
);

CREATE TABLE totp_recovery_codes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash       BYTEA NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    used_at         TIMESTAMPTZ,
    CONSTRAINT totp_recovery_code_hash_len CHECK (octet_length(code_hash) = 32)
);
CREATE INDEX totp_recovery_codes_user_unused_idx ON totp_recovery_codes(user_id) WHERE used_at IS NULL;

-- Account-wide Trystero room identity is deliberately separate from storage_nodes.
-- The room identifier is encrypted at rest with a key held outside PostgreSQL (KMS/secret manager).
-- It is a rendezvous label, NEVER an authentication/authorization credential.
CREATE TABLE account_sync_identities (
    user_id                 UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    room_id_ciphertext      BYTEA NOT NULL,
    encryption_key_version  TEXT NOT NULL,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at              TIMESTAMPTZ
);

-- -----------------------------------------------------------------------------
-- Devices and cryptographic keys
-- -----------------------------------------------------------------------------

CREATE TABLE devices (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    device_name             TEXT NOT NULL,
    device_type             TEXT NOT NULL CHECK (
                                device_type IN ('browser', 'desktop', 'mobile', 'nas', 'server', 'other')
                            ),
    platform                TEXT,
    app_version             TEXT,
    -- public_key is Ed25519 public key in raw 32-byte form (Base64 only at the JSON boundary).
    public_key              BYTEA NOT NULL,
    signing_algorithm       TEXT NOT NULL DEFAULT 'Ed25519' CHECK (signing_algorithm = 'Ed25519'),
    -- X25519 public key, raw 32-byte form, for device-to-device key-envelope exchange.
    encryption_public_key   BYTEA NOT NULL,
    encryption_algorithm    TEXT NOT NULL DEFAULT 'X25519' CHECK (encryption_algorithm = 'X25519'),
    signing_key_version     INTEGER NOT NULL DEFAULT 1 CHECK (signing_key_version > 0),
    encryption_key_version  INTEGER NOT NULL DEFAULT 1 CHECK (encryption_key_version > 0),
    status                  TEXT NOT NULL DEFAULT 'active'
                            CHECK (status IN ('pending', 'active', 'revoked', 'blocked')),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at            TIMESTAMPTZ,
    revoked_at              TIMESTAMPTZ,
    CONSTRAINT devices_ed25519_public_key_len CHECK (octet_length(public_key) = 32),
    CONSTRAINT devices_x25519_public_key_len CHECK (octet_length(encryption_public_key) = 32),
    CONSTRAINT devices_revocation_consistency CHECK (
        (status = 'revoked' AND revoked_at IS NOT NULL) OR status <> 'revoked'
    ),
    UNIQUE (id, user_id)
);
CREATE INDEX devices_user_status_idx ON devices(user_id, status);

CREATE TABLE device_key_history (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id           UUID NOT NULL,
    user_id             UUID NOT NULL,
    key_purpose         TEXT NOT NULL CHECK (key_purpose IN ('signing', 'encryption')),
    algorithm           TEXT NOT NULL CHECK (algorithm IN ('Ed25519', 'X25519')),
    key_version         INTEGER NOT NULL CHECK (key_version > 0),
    public_key          BYTEA NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at       TIMESTAMPTZ,
    FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE,
    UNIQUE (device_id, key_purpose, key_version),
    CONSTRAINT device_key_history_public_key_len CHECK (octet_length(public_key) = 32)
);

-- -----------------------------------------------------------------------------
-- Vaults and opaque key envelopes (server never receives VMK/recovery phrase)
-- -----------------------------------------------------------------------------

CREATE TABLE vaults (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
    crypto_version  INTEGER NOT NULL DEFAULT 1 CHECK (crypto_version > 0),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE key_envelopes (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id                    UUID NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id                     UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    envelope_type               TEXT NOT NULL CHECK (envelope_type IN ('recovery', 'device')),
    device_id                   UUID,
    format_id                   TEXT NOT NULL,
    format_version              INTEGER NOT NULL CHECK (format_version > 0),
    key_derivation_algorithm    TEXT NOT NULL,
    key_derivation_params       JSONB NOT NULL DEFAULT '{}'::jsonb,
    cipher_algorithm            TEXT NOT NULL CHECK (cipher_algorithm = 'AES-256-GCM'),
    salt                        BYTEA,
    nonce                       BYTEA NOT NULL,
    ciphertext                  BYTEA NOT NULL,
    aad_version                 INTEGER NOT NULL DEFAULT 1 CHECK (aad_version > 0),
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE CASCADE,
    CONSTRAINT key_envelope_nonce_len CHECK (octet_length(nonce) = 12),
    CONSTRAINT key_envelope_salt_len CHECK (salt IS NULL OR octet_length(salt) = 16),
    CONSTRAINT key_envelope_type_device_check CHECK (
        (envelope_type = 'recovery' AND device_id IS NULL) OR
        (envelope_type = 'device' AND device_id IS NOT NULL)
    ),
    CONSTRAINT key_envelope_recovery_kdf_check CHECK (
        envelope_type <> 'recovery' OR
        (format_id = 'vault-envelope-v1' AND key_derivation_algorithm = 'Argon2id'
         AND key_derivation_params->>'memory_kib' = '65536'
         AND key_derivation_params->>'iterations' = '3'
         AND key_derivation_params->>'parallelism' = '1'
         AND key_derivation_params->>'output_length' = '32'
         AND salt IS NOT NULL)
    )
);
CREATE UNIQUE INDEX key_envelopes_one_recovery_idx ON key_envelopes(vault_id) WHERE envelope_type = 'recovery';
CREATE UNIQUE INDEX key_envelopes_one_per_device_idx ON key_envelopes(vault_id, device_id) WHERE envelope_type = 'device';
CREATE INDEX key_envelopes_user_idx ON key_envelopes(user_id);

-- -----------------------------------------------------------------------------
-- Storage nodes and node-agent credentials
-- -----------------------------------------------------------------------------

CREATE TABLE storage_nodes (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id               UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    device_id                   UUID,
    node_type                   TEXT NOT NULL CHECK (
                                    node_type IN ('browser_p2p', 'desktop_p2p', 'nas', 'vps', 'dedicated_server')
                                ),
    display_name                TEXT NOT NULL,
    status                      TEXT NOT NULL DEFAULT 'pending'
                                CHECK (status IN ('pending', 'online', 'offline', 'degraded', 'suspended', 'retired')),
    region                      TEXT,
    country_code                CHAR(2),
    total_capacity_bytes        BIGINT NOT NULL DEFAULT 0 CHECK (total_capacity_bytes >= 0),
    available_capacity_bytes    BIGINT NOT NULL DEFAULT 0 CHECK (available_capacity_bytes >= 0),
    verified_capacity_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (verified_capacity_bytes >= 0),
    capabilities                JSONB NOT NULL DEFAULT '{}'::jsonb,
    hardware_info               JSONB NOT NULL DEFAULT '{}'::jsonb,
    network_info                JSONB NOT NULL DEFAULT '{}'::jsonb,
    last_heartbeat_at           TIMESTAMPTZ,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    retired_at                  TIMESTAMPTZ,
    FOREIGN KEY (device_id, owner_user_id) REFERENCES devices(id, user_id) ON DELETE RESTRICT,
    CONSTRAINT storage_node_capacity_bounds CHECK (
        available_capacity_bytes <= total_capacity_bytes AND
        verified_capacity_bytes <= total_capacity_bytes
    )
);
CREATE INDEX storage_nodes_owner_idx ON storage_nodes(owner_user_id, status);
CREATE INDEX storage_nodes_search_idx ON storage_nodes(status, region, node_type);

CREATE TABLE node_api_keys (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id         UUID NOT NULL REFERENCES storage_nodes(id) ON DELETE CASCADE,
    key_prefix      TEXT NOT NULL,
    key_hash        BYTEA NOT NULL UNIQUE,
    scopes          TEXT[] NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ,
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    CONSTRAINT node_api_key_hash_len CHECK (octet_length(key_hash) = 32),
    CONSTRAINT node_api_key_prefix_len CHECK (length(key_prefix) BETWEEN 4 AND 20),
    CONSTRAINT node_api_key_scopes_nonempty CHECK (cardinality(scopes) > 0)
);
CREATE INDEX node_api_keys_node_active_idx ON node_api_keys(node_id) WHERE revoked_at IS NULL;

CREATE TABLE node_heartbeats (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    node_id                     UUID NOT NULL REFERENCES storage_nodes(id) ON DELETE CASCADE,
    api_key_id                  UUID REFERENCES node_api_keys(id) ON DELETE SET NULL,
    heartbeat_sequence          BIGINT NOT NULL CHECK (heartbeat_sequence > 0),
    agent_version               TEXT,
    observed_at                 TIMESTAMPTZ NOT NULL,
    received_at                 TIMESTAMPTZ NOT NULL DEFAULT now(),
    total_capacity_bytes        BIGINT NOT NULL CHECK (total_capacity_bytes >= 0),
    available_capacity_bytes    BIGINT NOT NULL CHECK (available_capacity_bytes >= 0),
    telemetry                   JSONB NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (node_id, heartbeat_sequence),
    CONSTRAINT node_heartbeat_capacity_bounds CHECK (available_capacity_bytes <= total_capacity_bytes)
);
CREATE INDEX node_heartbeats_node_time_idx ON node_heartbeats(node_id, received_at DESC);

-- -----------------------------------------------------------------------------
-- Logical quota accounting, reports, placements and storage verification
-- -----------------------------------------------------------------------------

CREATE TABLE storage_usage_accounts (
    user_id                     UUID PRIMARY KEY REFERENCES users(id) ON DELETE RESTRICT,
    -- Initial policy assumption: 500 MB decimal = 500,000,000 bytes. Product owner must confirm.
    free_quota_bytes            BIGINT NOT NULL DEFAULT 500000000 CHECK (free_quota_bytes >= 0),
    logical_used_bytes          BIGINT NOT NULL DEFAULT 0 CHECK (logical_used_bytes >= 0),
    logical_reserved_bytes      BIGINT NOT NULL DEFAULT 0 CHECK (logical_reserved_bytes >= 0),
    physical_used_bytes         BIGINT NOT NULL DEFAULT 0 CHECK (physical_used_bytes >= 0),
    verified_physical_bytes     BIGINT NOT NULL DEFAULT 0 CHECK (verified_physical_bytes >= 0),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT usage_verified_not_above_physical CHECK (verified_physical_bytes <= physical_used_bytes)
);

CREATE TABLE storage_quota_reservations (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    object_id           UUID NOT NULL,
    reserved_bytes      BIGINT NOT NULL CHECK (reserved_bytes > 0),
    status              TEXT NOT NULL DEFAULT 'active'
                        CHECK (status IN ('active', 'committed', 'released', 'expired')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,
    completed_at        TIMESTAMPTZ,
    CONSTRAINT quota_reservation_expiry CHECK (expires_at > created_at)
);
CREATE INDEX quota_reservations_user_active_idx ON storage_quota_reservations(user_id, expires_at) WHERE status = 'active';

CREATE TABLE storage_usage_reports (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_report_id        UUID NOT NULL,
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    device_id               UUID NOT NULL,
    report_sequence         BIGINT NOT NULL CHECK (report_sequence > 0),
    schema_version          INTEGER NOT NULL CHECK (schema_version = 1),
    generated_at            TIMESTAMPTZ NOT NULL,
    received_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    signing_key_version     INTEGER NOT NULL CHECK (signing_key_version > 0),
    signature               BYTEA NOT NULL,
    signed_payload_sha256   BYTEA NOT NULL,
    processing_status       TEXT NOT NULL DEFAULT 'accepted'
                            CHECK (processing_status IN ('accepted', 'rejected', 'superseded')),
    rejection_code          TEXT,
    FOREIGN KEY (device_id, user_id) REFERENCES devices(id, user_id) ON DELETE RESTRICT,
    UNIQUE (device_id, report_sequence),
    UNIQUE (device_id, client_report_id),
    UNIQUE (id, user_id),
    CONSTRAINT usage_report_signature_len CHECK (octet_length(signature) = 64),
    CONSTRAINT usage_report_payload_hash_len CHECK (octet_length(signed_payload_sha256) = 32)
);
CREATE INDEX storage_usage_reports_user_received_idx ON storage_usage_reports(user_id, received_at DESC);

CREATE TABLE storage_objects (
    user_id                 UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    object_id               UUID NOT NULL,
    current_revision        BIGINT NOT NULL CHECK (current_revision > 0),
    logical_size_bytes      BIGINT NOT NULL CHECK (logical_size_bytes >= 0),
    ciphertext_size_bytes   BIGINT NOT NULL CHECK (ciphertext_size_bytes >= 0),
    object_status           TEXT NOT NULL CHECK (object_status IN ('active', 'deleted')),
    last_report_id          UUID,
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, object_id),
    FOREIGN KEY (last_report_id, user_id) REFERENCES storage_usage_reports(id, user_id) ON DELETE RESTRICT,
    CONSTRAINT deleted_object_sizes_zero CHECK (
        object_status <> 'deleted' OR (logical_size_bytes = 0 AND ciphertext_size_bytes = 0)
    )
);
CREATE INDEX storage_objects_user_active_idx ON storage_objects(user_id) WHERE object_status = 'active';

CREATE TABLE storage_usage_items (
    report_id               UUID NOT NULL REFERENCES storage_usage_reports(id) ON DELETE CASCADE,
    object_id               UUID NOT NULL,
    revision                BIGINT NOT NULL CHECK (revision > 0),
    logical_size_bytes      BIGINT NOT NULL CHECK (logical_size_bytes >= 0),
    ciphertext_size_bytes   BIGINT NOT NULL CHECK (ciphertext_size_bytes >= 0),
    object_status           TEXT NOT NULL CHECK (object_status IN ('active', 'deleted')),
    PRIMARY KEY (report_id, object_id),
    CONSTRAINT usage_item_deleted_sizes_zero CHECK (
        object_status <> 'deleted' OR (logical_size_bytes = 0 AND ciphertext_size_bytes = 0)
    )
);

CREATE TABLE storage_placements (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id                 UUID NOT NULL,
    object_id               UUID NOT NULL,
    node_id                 UUID NOT NULL REFERENCES storage_nodes(id) ON DELETE RESTRICT,
    content_address         TEXT,
    ciphertext_size_bytes   BIGINT NOT NULL CHECK (ciphertext_size_bytes >= 0),
    placement_status        TEXT NOT NULL DEFAULT 'pending'
                            CHECK (placement_status IN ('pending', 'stored', 'verifying', 'verified', 'failed', 'removed')),
    placed_at               TIMESTAMPTZ,
    last_verified_at        TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    FOREIGN KEY (user_id, object_id) REFERENCES storage_objects(user_id, object_id) ON DELETE RESTRICT,
    UNIQUE (user_id, object_id, node_id)
);
CREATE INDEX storage_placements_object_idx ON storage_placements(user_id, object_id, placement_status);
CREATE INDEX storage_placements_node_idx ON storage_placements(node_id, placement_status);

CREATE TABLE storage_verification_challenges (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    placement_id            UUID NOT NULL REFERENCES storage_placements(id) ON DELETE CASCADE,
    challenge_type          TEXT NOT NULL CHECK (challenge_type IN ('random_read', 'integrity_sample')),
    nonce_hash              BYTEA NOT NULL,
    issued_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at              TIMESTAMPTZ NOT NULL,
    completed_at            TIMESTAMPTZ,
    challenge_status        TEXT NOT NULL DEFAULT 'pending'
                            CHECK (challenge_status IN ('pending', 'passed', 'failed', 'expired')),
    CONSTRAINT storage_challenge_nonce_hash_len CHECK (octet_length(nonce_hash) = 32),
    CONSTRAINT storage_challenge_expiry CHECK (expires_at > issued_at)
);
CREATE INDEX storage_challenges_pending_idx ON storage_verification_challenges(expires_at) WHERE challenge_status = 'pending';

CREATE TABLE storage_verification_receipts (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    challenge_id            UUID NOT NULL UNIQUE REFERENCES storage_verification_challenges(id) ON DELETE CASCADE,
    response_digest         BYTEA,
    verification_passed     BOOLEAN NOT NULL,
    verified_bytes          BIGINT NOT NULL DEFAULT 0 CHECK (verified_bytes >= 0),
    result_details          JSONB NOT NULL DEFAULT '{}'::jsonb,
    received_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    verified_at             TIMESTAMPTZ,
    CONSTRAINT verification_response_digest_len CHECK (
        response_digest IS NULL OR octet_length(response_digest) = 32
    )
);


-- Implementation invariants not expressible as simple CHECK constraints:
-- 1. For each report, verify Ed25519 over RFC 8785 JCS UTF-8 bytes of the `payload` object;
--    signature is excluded from the signed object. Reject unknown fields/schema versions.
-- 2. Require report device_id to belong to authenticated user and require active device/key.
-- 3. report_sequence must increase monotonically per device. Idempotent replay of the same
--    client_report_id + same payload hash returns the original result; same id with changed
--    payload is a conflict.
-- 4. storage_usage_items are deltas. Omitted object_ids mean "no change"; deletion requires
--    an explicit higher-revision tombstone with status=deleted and both sizes equal to zero.
-- 5. Update storage_objects and storage_usage_accounts in one transaction. Accept a newer
--    revision; same revision with different values is a conflict; older revision is superseded.
-- 6. logical_used_bytes counts each active (user_id, object_id) exactly once, irrespective of
--    the number of replicas/devices. Client-reported sizes are accounting claims, not proof.
-- 7. physical_used_bytes and verified_physical_bytes are derived from node placements/receipts,
--    never trusted from a browser's storage/usage report.
-- 8. Enforce quota reservations transactionally before placing a new logical object. The
--    storage_quota_reservations table is the foundation; a reservation API is still required.
-- 9. Do not expose node_api_keys, key_envelopes, public peer rendezvous details, or room IDs in
--    public node catalog responses. Node rendezvous credentials must be short-lived.
-- 10. Do not cascade-delete account data in production without a separate data-retention policy.
