// ============================================================
//  functions/_utils/bulletin.js
//  Announcements + events, stored in D1 (`witi_users`).
//
//  Shapes, matching what the pages already render:
//
//      announcement = { id, message, detail, createdAt }
//      event        = { id, kind: "school"|"club", message,
//                       date: "YYYY-MM-DD", createdAt }
//
//  Reading is public (the bulletin board is for students), writing
//  is admin-only -- the endpoints check the session cookie before
//  calling anything here.
//
//  Every string is validated here rather than only in the browser:
//  a form's maxlength is a convenience, not a guarantee.
// ============================================================
import { json, now } from "./admin.js";

const DB_BINDING = "witi_users";

const MAX_MESSAGE = 200;
const MAX_DETAIL = 2000;
const EVENT_KINDS = ["school", "club"];

function db(env) {
  const database = env?.[DB_BINDING];
  if (!database) {
    throw new Error(
      `D1 binding "${DB_BINDING}" is missing. Check wrangler.toml.`,
    );
  }
  return database;
}

// --- Validation --------------------------------------------------
export function validateAnnouncement(body) {
  const message = String(body?.message ?? "").trim();
  const detail = String(body?.detail ?? "").trim();

  if (!message) return { error: "The message is required." };
  if (message.length > MAX_MESSAGE) {
    return { error: `The message must be ${MAX_MESSAGE} characters or fewer.` };
  }
  if (detail.length > MAX_DETAIL) {
    return { error: `The details must be ${MAX_DETAIL} characters or fewer.` };
  }
  return { message, detail };
}

export function validateEvent(body) {
  const kind = String(body?.kind ?? "").trim().toLowerCase();
  const message = String(body?.message ?? "").trim();
  const date = String(body?.date ?? "").trim();

  if (!EVENT_KINDS.includes(kind)) {
    return { error: "The board must be 'school' or 'club'." };
  }
  if (!message) return { error: "The event is required." };
  if (message.length > MAX_MESSAGE) {
    return { error: `The event must be ${MAX_MESSAGE} characters or fewer.` };
  }
  if (!isIsoDate(date)) {
    return { error: "The date must be a real date in YYYY-MM-DD form." };
  }
  return { kind, message, date };
}

// "2026-07-20" and nothing else -- also rejects 2026-02-31.
function isIsoDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const [y, m, d] = value.split("-").map(Number);
  const date = new Date(Date.UTC(y, m - 1, d));
  return (
    date.getUTCFullYear() === y &&
    date.getUTCMonth() === m - 1 &&
    date.getUTCDate() === d
  );
}

// --- Reads -------------------------------------------------------
function rowToAnnouncement(row) {
  return {
    id: row.announcement_id,
    message: row.message,
    detail: row.detail,
    createdAt: new Date(row.created_at * 1000).toISOString(),
  };
}

function rowToEvent(row) {
  return {
    id: row.event_id,
    kind: row.kind,
    message: row.message,
    date: row.event_date,
    createdAt: new Date(row.created_at * 1000).toISOString(),
  };
}

export async function listAnnouncements(env) {
  const { results } = await db(env)
    .prepare(
      `SELECT announcement_id, message, detail, created_at
         FROM announcements
        ORDER BY created_at DESC, announcement_id DESC`,
    )
    .all();
  return (results || []).map(rowToAnnouncement);
}

export async function listEvents(env, kind) {
  const query = kind
    ? `SELECT event_id, kind, message, event_date, created_at
         FROM events
        WHERE kind = ?1
        ORDER BY event_date ASC, event_id ASC`
    : `SELECT event_id, kind, message, event_date, created_at
         FROM events
        ORDER BY event_date ASC, event_id ASC`;
  const statement = db(env).prepare(query);
  const { results } = kind
    ? await statement.bind(kind).all()
    : await statement.all();
  return (results || []).map(rowToEvent);
}

// Everything the board needs, in one round trip.
export async function listBulletin(env) {
  const [announcements, events] = await Promise.all([
    listAnnouncements(env),
    listEvents(env),
  ]);
  return {
    announcements,
    events: {
      school: events.filter((event) => event.kind === "school"),
      club: events.filter((event) => event.kind === "club"),
    },
  };
}

// --- Writes ------------------------------------------------------
export async function addAnnouncement(env, { message, detail }) {
  const result = await db(env)
    .prepare(
      `INSERT INTO announcements (message, detail, created_at)
       VALUES (?1, ?2, ?3)`,
    )
    .bind(message, detail, now())
    .run();

  const row = await db(env)
    .prepare(
      `SELECT announcement_id, message, detail, created_at
         FROM announcements WHERE announcement_id = ?1`,
    )
    .bind(result.meta.last_row_id)
    .first();
  return rowToAnnouncement(row);
}

export async function addEvent(env, { kind, message, date }) {
  const result = await db(env)
    .prepare(
      `INSERT INTO events (kind, message, event_date, created_at)
       VALUES (?1, ?2, ?3, ?4)`,
    )
    .bind(kind, message, date, now())
    .run();

  const row = await db(env)
    .prepare(
      `SELECT event_id, kind, message, event_date, created_at
         FROM events WHERE event_id = ?1`,
    )
    .bind(result.meta.last_row_id)
    .first();
  return rowToEvent(row);
}

// Returns true when a row was actually deleted.
export async function deleteAnnouncement(env, id) {
  const result = await db(env)
    .prepare("DELETE FROM announcements WHERE announcement_id = ?1")
    .bind(id)
    .run();
  return result.meta.changes > 0;
}

export async function deleteEvent(env, id) {
  const result = await db(env)
    .prepare("DELETE FROM events WHERE event_id = ?1")
    .bind(id)
    .run();
  return result.meta.changes > 0;
}

// --- Shared response helper -------------------------------------
// The admin endpoints all need the same "must be logged in" gate.
export function unauthorized() {
  return json({ error: "Log in as an admin first." }, 401);
}

// Parses an id from a URL segment; returns null when it is not a
// positive integer, so callers can answer 400 instead of querying.
export function parseId(value) {
  const id = Number(Array.isArray(value) ? value[0] : value);
  return Number.isInteger(id) && id > 0 ? id : null;
}
