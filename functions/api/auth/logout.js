// ============================================================
//  functions/api/auth/logout.js
//  POST /api/auth/logout
//
//  Deletes the session row and clears the cookie.
//
//  Deleting the row is the part that matters -- clearing the
//  cookie alone would leave a valid token alive in the database
//  for anyone who had already copied it.
// ============================================================

import {
  json,
  DB_BINDING,
  buildSessionCookie,
} from "../../_utils/auth.js";
import { hashSessionToken } from "../../_utils/password.js";

function readSessionCookie(request) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/(?:^|;\s*)session=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

export async function onRequestPost({ request, env }) {
  const db = env[DB_BINDING];
  const token = readSessionCookie(request);

  if (token && db) {
    const tokenHash = await hashSessionToken(token);
    await db
      .prepare("DELETE FROM sessions WHERE token_hash = ?")
      .bind(tokenHash)
      .run();
  }

  // Logout is idempotent: already-logged-out still returns ok, and
  // the cookie is expired either way.
  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      "content-type": "application/json",
      "Set-Cookie": buildSessionCookie("", 0, request.url, env),
    },
  });
}
