CREATE TABLE console_passkeys (
    credential_id bytea PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    rp_id text NOT NULL,
    credential bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);

CREATE INDEX console_passkeys_user_rp_idx ON console_passkeys (user_id, rp_id);

CREATE TABLE console_passkey_challenges (
    digest bytea PRIMARY KEY,
    operation text NOT NULL CHECK (operation IN ('registration', 'authentication')),
    user_id uuid REFERENCES users(id) ON DELETE CASCADE,
    rp_id text NOT NULL,
    payload bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    CHECK ((operation = 'registration') = (user_id IS NOT NULL))
);

CREATE INDEX console_passkey_challenges_expiry_idx ON console_passkey_challenges (expires_at);

CREATE TRIGGER wahb_writer_fence_guard BEFORE INSERT OR UPDATE OR DELETE ON console_passkeys
    FOR EACH ROW EXECUTE FUNCTION wahb_enforce_writer_fence();
CREATE TRIGGER wahb_writer_fence_guard BEFORE INSERT OR UPDATE OR DELETE ON console_passkey_challenges
    FOR EACH ROW EXECUTE FUNCTION wahb_enforce_writer_fence();
