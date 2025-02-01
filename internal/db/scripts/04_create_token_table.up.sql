
CREATE TABLE IF NOT EXISTS auth.tokens (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES auth.users(id) NOT NULL,
    jti TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN DEFAULT FALSE
);
