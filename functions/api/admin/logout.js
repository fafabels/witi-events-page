// POST /api/admin/logout -- clears the session cookie.
import { json, clearSessionCookie } from "../../_utils/admin.js";

export async function onRequestPost({ request }) {
  return json({ ok: true }, 200, { "set-cookie": clearSessionCookie(request) });
}
