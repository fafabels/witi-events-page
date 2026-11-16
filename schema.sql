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

    -- Strict student-id template: SJ, batch year, dash, 4 digits  (e.g. SJ23-0001)
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

    -- Strict student-id template: SJ, batch year, dash, 4 digits  (e.g. SJ23-0001)
    -- Must match the users table and the signup/admin validation exactly.
    CONSTRAINT ck_master_student_id_format
        CHECK (student_id GLOB 'SJ[0-9][0-9]-[0-9][0-9][0-9][0-9]')
);

-- Example rows:
--   INSERT INTO student_master_list (student_id, name) VALUES
--     ('SJ23-0001', 'Juan Dela Cruz'),
--     ('SJ23-0002', 'Maria Santos');

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

-- ============================================================
--  Pending email changes — confirms a new Gmail address.
--
--  A change is only applied when the link that was mailed to the
--  NEW address is opened. The row stores only the SHA-256 of the
--  link's random token, exactly like `sessions`.
--
--  Created by the account endpoint if it does not exist yet, so this
--  block is safe to run against an already-populated database.
-- ============================================================

CREATE TABLE IF NOT EXISTS email_change_requests (
    token_hash      TEXT    PRIMARY KEY,          -- SHA-256(token) of the mailed link
    user_id         INTEGER NOT NULL,             -- whose email is changing
    new_email       TEXT    NOT NULL,             -- address waiting to be confirmed
    created_at      INTEGER NOT NULL,             -- epoch seconds
    expires_at      INTEGER NOT NULL,             -- epoch seconds

    FOREIGN KEY (user_id) REFERENCES users (user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_email_change_user_id
    ON email_change_requests (user_id);

-- ============================================================
--  Bulletin content — what the bulletin page displays.
--
--  announcements  -> #a_con   (short message + click/hover detail)
--  events         -> #se_ann_con (kind = 'school') and
--                    #ce_ann_con (kind = 'club')
--
--  event_date is stored as TEXT in strict YYYY-MM-DD form so it
--  sorts correctly with a plain ORDER BY. The admin page takes a
--  date picker and the bulletin page formats it as "July 20, 2020".
-- ============================================================

DROP TABLE IF EXISTS announcements;

CREATE TABLE IF NOT EXISTS announcements (
    announcement_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    message          TEXT NOT NULL,          -- the short line shown on the board
    detail           TEXT NOT NULL DEFAULT '', -- shown on click / hover
    created_at       INTEGER NOT NULL        -- epoch seconds
);

DROP TABLE IF EXISTS events;

CREATE TABLE IF NOT EXISTS events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL
                    CHECK (kind IN ('school', 'club')),   -- which column it lands in
    message     TEXT NOT NULL,                            -- what is going to happen
    event_date  TEXT NOT NULL,                            -- YYYY-MM-DD
    created_at  INTEGER NOT NULL,                         -- epoch seconds

    CONSTRAINT ck_events_date_format
        CHECK (event_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
);

CREATE INDEX IF NOT EXISTS idx_events_kind_date ON events (kind, event_date);

-- ============================================================
--  Staying logged in on the local dev server
--
--  wrangler.toml files are NOT watched by `wrangler pages dev`, so a
--  value added there is not picked up without a restart. Passing it
--  on the command line always works:
--
--    npx wrangler pages dev --port 8788 \
--        --binding SESSION_COOKIE_INSECURE=1
--
--  With that set, the session cookie drops the `Secure` flag and is
--  stored over plain http:// (including http://192.168.x.x on your
--  phone). Never set it in production.
-- ============================================================
