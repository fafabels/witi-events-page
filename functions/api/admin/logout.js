// POST /api/admin/logout -- deletes the session row and clears
// the cookie. Logging out on one device leaves other devices alone.
import {
  json,
  clearSessionCookie,
  destroySession,
} from "../../_utils/admin.js";

export async function onRequestPost({ request, env }) {
  try {
    await destroySession(request, env);
  } catch {
    // The cookie is cleared below either way.
  }
  return json({ ok: true }, 200, { "set-cookie": clearSessionCookie(request) });
}
