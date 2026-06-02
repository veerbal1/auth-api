CREATE TABLE sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token TEXT NOT NULL,
    email TEXT NOT NULL REFERENCES users(email),
    created_at BIGINT NOT NULL
);