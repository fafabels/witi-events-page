// ============================================================
//  functions/api/bulletin.js
//  Bulletin content: announcements + events.
//
//    GET    /api/bulletin            -> everything the board shows
//    POST   /api/bulletin            -> add one item (admins only)
//    DELETE /api/bulletin            -> remove one item (admins only)
//
//  GET is public on purpose: the bulletin board is readable by
//  anyone who can open the page. Writes are admin-only and are
//  re-checked here with requireAdmin -- the admin page's own
//  guard is UX only, never a security boundary.
//
//  POST body shapes:
//    { type: "announcement", message, detail }
//    { type: "event", kind: "school" | "club", message, date: "YYYY-MM-DD" }
//
//  DELETE body shapes:
//    { type: "announcement", id }
//    { type: "event", id }
// ============================================================

import { requireAdmin, json } from "../_utils/auth.js";

const EVENT_KINDS = new Set(["school", "club"]);

// --- Validation -------------------------------------------------
function normalizeText(raw, { min, max, field }) {
  const value = String(raw ?? "")
    .trim()
    .replace(/\s+/g, " ");
  if (value.length < min || value.length > max) {
    return {
      ok: false,
      error: `${field} must be between ${min} and ${max} characters.`,
    };
  }
  return { ok: true, value };
}

// Accepts only a real calendar date written as YYYY-MM-DD.
// (The <input type="date"> in the admin page already produces this,
// but the endpoint must not trust the browser.)
function normalizeDate(raw) {
  const value = String(raw ?? "").trim();
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
    return { ok: false, error: "Date must be in YYYY-MM-DD format." };
  }
  const [y, m, d] = value.split("-").map(Number);
  const parsed = new Date(Date.UTC(y, m - 1, d));
  if (
    parsed.getUTCFullYear() !== y ||
    parsed.getUTCMonth() !== m - 1 ||
    parsed.getUTCDate() !== d
  ) {
    return { ok: false, error: "That date does not exist." };
  }
  return { ok: true, value };
}

function normalizeId(raw) {
  const id = Number(raw);
  if (!Number.isInteger(id) || id <= 0) {
    return { ok: false, error: "A valid id is required." };
  }
  return { ok: true, value: id };
}

// --- GET: everything the board needs, in one round trip ---------
export async function onRequestGet({ env }) {
  const db = env.witi_users;

  const [announcements, events] = await Promise.all([
    db
      .prepare(
        `SELECT announcement_id AS id, message, detail
           FROM announcements
          ORDER BY created_at DESC, announcement_id DESC`,
      )
      .all(),
    db
      .prepare(
        `SELECT event_id AS id, kind, message, event_date AS date
           FROM events
          ORDER BY event_date ASC, event_id ASC`,
      )
      .all(),
  ]);

  return json({
    announcements: announcements.results,
    events: events.results,
  });
}

// --- POST: add an announcement or an event ----------------------
export async function onRequestPost({ request, env }) {
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const now = Math.floor(Date.now() / 1000);

  if (body.type === "announcement") {
    const message = normalizeText(body.message, {
      min: 1,
      max: 200,
      field: "Message",
    });
    if (!message.ok) return json({ error: message.error }, 422);

    // Detail is optional; an empty string means "nothing more to show".
    const detail = normalizeText(body.detail ?? "", {
      min: 0,
      max: 2000,
      field: "Details",
    });
    if (!detail.ok) return json({ error: detail.error }, 422);

    const result = await env.witi_users
      .prepare(
        `INSERT INTO announcements (message, detail, created_at)
         VALUES (?, ?, ?)`,
      )
      .bind(message.value, detail.value, now)
      .run();

    return json(
      {
        ok: true,
        announcement: {
          id: result.meta.last_row_id,
          message: message.value,
          detail: detail.value,
        },
      },
      201,
    );
  }

  if (body.type === "event") {
    const kind = String(body.kind ?? "")
      .trim()
      .toLowerCase();
    if (!EVENT_KINDS.has(kind)) {
      return json({ error: "Event kind must be 'school' or 'club'." }, 422);
    }

    const message = normalizeText(body.message, {
      min: 1,
      max: 200,
      field: "Event",
    });
    if (!message.ok) return json({ error: message.error }, 422);

    const date = normalizeDate(body.date);
    if (!date.ok) return json({ error: date.error }, 422);

    const result = await env.witi_users
      .prepare(
        `INSERT INTO events (kind, message, event_date, created_at)
         VALUES (?, ?, ?, ?)`,
      )
      .bind(kind, message.value, date.value, now)
      .run();

    return json(
      {
        ok: true,
        event: {
          id: result.meta.last_row_id,
          kind,
          message: message.value,
          date: date.value,
        },
      },
      201,
    );
  }

  return json({ error: "type must be 'announcement' or 'event'." }, 422);
}

// --- DELETE: remove one item ------------------------------------
export async function onRequestDelete({ request, env }) {
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const id = normalizeId(body.id);
  if (!id.ok) return json({ error: id.error }, 422);

  let result;
  if (body.type === "announcement") {
    result = await env.witi_users
      .prepare("DELETE FROM announcements WHERE announcement_id = ?")
      .bind(id.value)
      .run();
  } else if (body.type === "event") {
    result = await env.witi_users
      .prepare("DELETE FROM events WHERE event_id = ?")
      .bind(id.value)
      .run();
  } else {
    return json({ error: "type must be 'announcement' or 'event'." }, 422);
  }

  if (result.meta.changes === 0) {
    return json({ error: "That item no longer exists." }, 404);
  }

  return json({ ok: true, removed: id.value });
}
