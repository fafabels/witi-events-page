-- ============================================================
--  witi — users table
--  Target: Cloudflare D1 (SQLite)
--
--  Apply with:
--    npx wrangler d1 execute witi-db --file=./schema.sql --remote
--    npx wrangler d1 execute witi-db --file=./schema.sql --local
-- ============================================================

DROP TABLE IF EXISTS users;

CREATE TABLE IF NOT EXISTS users (
    user_id     INTEGER PRIMARY KEY AUTOINCREMENT,   -- auto-assigned numeric key
    name        TEXT    NOT NULL,                     -- user-made display name
    password    TEXT    NOT NULL,                     -- password HASH (never plaintext)
    student_id  TEXT    NOT NULL,                     -- must match the master list
    gmail       TEXT    NOT NULL,                     -- user-made email
    access      TEXT    NOT NULL DEFAULT 'user'
                    CHECK (access IN ('user', 'admin')),

    -- Strict student-id template: SJ, batch year, dash, 4 digits  (e.g. 2023-0001)
    CONSTRAINT ck_users_student_id_format
        CHECK (student_id GLOB 'SJ[0-9][0-9]-[0-9][0-9][0-9][0-9]'), -- SJ00-0000

    -- Uniqueness / integrity rules
    CONSTRAINT uq_users_gmail       UNIQUE (gmail),
    CONSTRAINT uq_users_student_id  UNIQUE (student_id)
);

-- Fast lookup on login (email) and on student-id validation
CREATE INDEX idx_users_gmail      ON users (gmail);
CREATE INDEX idx_users_student_id ON users (student_id);

-- ============================================================
--  Student ID master list — student_id must match one of these.
--  Populate it with your official roster.
-- ============================================================

DROP TABLE IF EXISTS student_master_list;

CREATE TABLE IF NOT EXISTS student_master_list (
    student_id  TEXT PRIMARY KEY,          -- the ID (one per student)
    name        TEXT NOT NULL,             -- the student's official name

    -- Strict student-id template: 4 digits, dash, 4 digits  (e.g. 2023-0001)
    CONSTRAINT ck_master_student_id_format
        CHECK (student_id GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9][0-9][0-9]')
);

-- Example rows:
--   INSERT INTO student_master_list (student_id, name) VALUES
--     ('2023-0001', 'Juan Dela Cruz'),
--     ('2023-0002', 'Maria Santos');

-- ============================================================
--  Sessions — server-side session store.
--
--  The cookie carries a random 64-char hex token. This table maps
--  the SHA-256 of that token to a user. Because the token is
--  random (not a user id), a hand-written cookie cannot select an
--  arbitrary account the way `session=1` could.
--
--  expires_at is stored as a Unix epoch (seconds, UTC) for cheap
--  numeric comparison and no timezone ambiguity.
-- ============================================================

DROP TABLE IF EXISTS sessions;

CREATE TABLE IF NOT EXISTS sessions (
    token_hash  TEXT    PRIMARY KEY,          -- SHA-256(token), base64
    user_id     INTEGER NOT NULL,             -- who this session belongs to
    created_at  INTEGER NOT NULL,             -- epoch seconds
    expires_at  INTEGER NOT NULL,             -- epoch seconds

    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

-- Cleanup + "log out everywhere" both scan by user.
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions (user_id);

-- Expired-row sweeps filter on expires_at.
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);
