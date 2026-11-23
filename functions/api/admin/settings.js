// ============================================================
//  functions/api/admin/settings.js
//  The security-mode switch on the admin page.
//
//    GET /api/admin/settings   -> { strict: true | false }
//    PUT /api/admin/settings   -> body { strict: boolean }
//
//  Admin-only, like every write on the site. The switch is stored in
//  the `site_settings` table and read by functions/_utils/settings.js,
//  which signup.js, login.js and /api/me consult on every request.
//  So flipping this changes what the SERVER allows -- the admin page's
//  own UI is only a reflection of it.
//
//  Turning strict mode OFF does not delete anyone's account and does
//  not touch `student_master_list`; it only stops requiring them.
//  Turning it back ON starts enforcing the roster and sessions again.
// ============================================================

import { requireAdmin, json, DB_BINDING } from "../../_utils/auth.js";
import { isStrictMode, setStrictMode } from "../../_utils/settings.js";

// The table lives in schema.sql, but a database created before this
// feature existed has no such table. CREATE TABLE IF NOT EXISTS is a
// no-op once it is there, so this makes the switch work without a
// manual migration step.
async function ensureSettingsTable(db) {
  await db
    .prepare(
      `CREATE TABLE IF NOT EXISTS site_settings (
         id           INTEGER PRIMARY KEY CHECK (id = 1),
         strict_mode  INTEGER NOT NULL DEFAULT 1 CHECK (strict_mode IN (0, 1)),
         updated_at   INTEGER NOT NULL
       )`,
    )
    .run();
}

export async function onRequestGet({ request, env }) {
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  const db = env[DB_BINDING];
  if (!db) return json({ error: "Server misconfigured." }, 500);

  await ensureSettingsTable(db);

  return json({
    strict: await isStrictMode(env),
    studentsOnRoster: await countRoster(db),
  });
}

export async function onRequestPut({ request, env }) {
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  const db = env[DB_BINDING];
  if (!db) return json({ error: "Server misconfigured." }, 500);

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  // Only a real boolean is accepted: `"false"` or 0 must not be
  // mistaken for a valid payload and silently close the site.
  if (typeof body.strict !== "boolean") {
    return json({ error: "The body must be { strict: true | false }." }, 422);
  }

  await ensureSettingsTable(db);
  await setStrictMode(env, body.strict);

  return json({ ok: true, strict: body.strict });
}

async function countRoster(db) {
  try {
    const row = await db
      .prepare("SELECT COUNT(*) AS n FROM student_master_list")
      .first();
    return row?.n ?? 0;
  } catch {
    return 0;
  }
}
