-- ============================================================
--  witi -- admin credentials + admin sessions
--  Target: Cloudflare D1 (SQLite)
--
--  Apply with:
--    npx wrangler d1 execute witi-users --file=./schema.sql --remote
--    npx wrangler d1 execute witi-users --file=./schema.sql --local
--
--  This file is safe to re-run: no DROP statements, every object
--  is CREATE ... IF NOT EXISTS, so existing admins are never wiped.
--
--  Read/written only through functions/_utils/admin.js.
-- ============================================================

-- ============================================================
--  Admin key - value pairs
--
--  One row per admin, entered on admin.html:
--      name     = "david"
--      password = "abcd12345678"   (stored as a PBKDF2 hash)
--
--  name_key is the lowercased name, so "David" and "david" are
--  the same admin, and the UNIQUE constraint keeps it that way.
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_credentials (
    admin_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL,                 -- as typed / displayed
    name_key      TEXT    NOT NULL UNIQUE,          -- lower(name), for login + uniqueness
    password_algo TEXT    NOT NULL DEFAULT 'pbkdf2-sha256',
    password_iters INTEGER NOT NULL DEFAULT 100000,
    password_salt TEXT    NOT NULL,                 -- base64 random salt
    password_hash TEXT    NOT NULL,                 -- base64 PBKDF2 hash -- never the password
    created_at    INTEGER NOT NULL,                 -- epoch seconds
    updated_at    INTEGER NOT NULL,                 -- epoch seconds
    CONSTRAINT ck_admin_name_length
        CHECK (length(name) BETWEEN 1 AND 32)
);

-- Login looks up by name_key, so that is the index that matters.
CREATE INDEX IF NOT EXISTS idx_admin_name_key ON admin_credentials (name_key);

-- ============================================================
--  Admin sessions
--
--  The cookie holds a random 32-byte token (hex). This table maps
--  the SHA-256 of that token to an admin row, so a hand-written
--  cookie ("witi_admin=1") matches nothing. Expiry is checked in
--  SQL, and the FK cascade means deleting an admin also drops
--  their sessions.
-- ============================================================
CREATE TABLE IF NOT EXISTS admin_sessions (
    token_hash  TEXT    PRIMARY KEY,                -- SHA-256 hex of the cookie token
    admin_id    INTEGER NOT NULL,
    created_at  INTEGER NOT NULL,                   -- epoch seconds
    expires_at  INTEGER NOT NULL,                   -- epoch seconds
    FOREIGN KEY (admin_id) REFERENCES admin_credentials (admin_id)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_admin_sessions_admin_id
    ON admin_sessions (admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at
    ON admin_sessions (expires_at);

-- ============================================================
--  Bulletin board content
--
--  These are what admin.html posts and bulletin.html renders.
--  Both edits are written only through functions/_utils/bulletin.js.
-- ============================================================

-- Announcements. `message` is the short line the board shows;
-- `detail` is the longer text revealed on hover / click / focus.
-- detail may be '' when the admin left it blank.
CREATE TABLE IF NOT EXISTS announcements (
    announcement_id INTEGER PRIMARY KEY AUTOINCREMENT,
    message         TEXT    NOT NULL,              -- short line
    detail          TEXT    NOT NULL DEFAULT '',   -- shown on hover / click
    created_at      INTEGER NOT NULL,              -- epoch seconds
    CONSTRAINT ck_announcements_message_length
        CHECK (length(message) BETWEEN 1 AND 200),
    CONSTRAINT ck_announcements_detail_length
        CHECK (length(detail) <= 2000)
);

-- Newest first is how both pages list them.
CREATE INDEX IF NOT EXISTS idx_announcements_created_at
    ON announcements (created_at DESC, announcement_id DESC);

-- Events, split over two boards by `kind`.
CREATE TABLE IF NOT EXISTS events (
    event_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    kind        TEXT NOT NULL
                    CHECK (kind IN ('school', 'club')),  -- which board
    message     TEXT NOT NULL,                           -- what is happening
    event_date  TEXT NOT NULL,                           -- YYYY-MM-DD (from <input type="date">)
    created_at  INTEGER NOT NULL,                        -- epoch seconds
    CONSTRAINT ck_events_message_length
        CHECK (length(message) BETWEEN 1 AND 200),
    CONSTRAINT ck_events_date_format
        CHECK (event_date GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]')
);

CREATE INDEX IF NOT EXISTS idx_events_kind_date
    ON events (kind, event_date);
