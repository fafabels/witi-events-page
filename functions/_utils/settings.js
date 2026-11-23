// ============================================================
//  functions/_utils/settings.js
//  One shared definition of the site's security mode.
//
//  The admin page has a switch:
//
//    strict = 1 (default)  Only students on student_master_list may
//                          sign up, and every page except the bulletin
//                          needs a logged-in student/admin.
//    strict = 0            "Open" mode: signup is not required at all,
//                          the bulletin reads are public, and there is no
//                          login/signup/account flow.
//
//  It lives in the database (not in this file) because it has to
//  survive a redeploy AND be readable by every Worker invocation. Every
//  endpoint asks THIS module, so the two layers (signup and the read
//  endpoints) can never disagree about which mode is on.
//
//  IMPORTANT: the mode only ever *relaxes* who may read the board. It
//  never relaxes requireAdmin -- writes stay admin-only in both modes.
// ============================================================

import { DB_BINDING } from "./auth.js";

// Single row, fixed id. See schema.sql.
const SETTINGS_ROW = 1;

/**
 * Read the current mode. Returns true (strict) when anything is
 * missing or unreadable -- failing closed is the safe default.
 * @param {object} env the Pages env (for the D1 binding)
 * @returns {Promise<boolean>}
 */
export async function isStrictMode(env) {
  const db = env?.[DB_BINDING];
  if (!db) return true; // no database -> never open the gate

  try {
    const row = await db
      .prepare("SELECT strict_mode FROM site_settings WHERE id = ?")
      .bind(SETTINGS_ROW)
      .first();
    if (!row) return true;
    return Number(row.strict_mode) !== 0;
  } catch (err) {
    // Table not created yet (database predates this feature) or a
    // transient D1 error: stay strict rather than silently opening up.
    console.error("could not read site_settings, assuming strict:", err);
    return true;
  }
}

/**
 * Write the mode. Admin-only callers must check that themselves;
 * this is only the storage.
 * @param {object} env
 * @param {boolean} strict
 */
export async function setStrictMode(env, strict) {
  const db = env[DB_BINDING];
  const now = Math.floor(Date.now() / 1000);
  const value = strict ? 1 : 0;

  await db
    .prepare(
      `INSERT INTO site_settings (id, strict_mode, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(id) DO UPDATE SET
         strict_mode = excluded.strict_mode,
         updated_at  = excluded.updated_at`,
    )
    .bind(SETTINGS_ROW, value, now)
    .run();
}

/**
 * Where a browser should be sent when it needs a session. In strict
 * mode that is the login page; in open mode the flow is gone, so the
 * bulletin board is the destination. Used by /api/me so the routing
 * choice is made by the server, not duplicated in every page.
 * @param {boolean} strict
 */
export function entryPage(strict) {
  return strict ? "/static/login/login.html" : "/static/user/bulletin.html";
}
