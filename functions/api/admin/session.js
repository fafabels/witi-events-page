// GET /api/admin/session -- who is logged in, if anyone.
// Pages use this to decide whether to show the admin tools or
// bounce back to the login page.
import { json, readSession } from "../../_utils/admin.js";

export async function onRequestGet({ request, env }) {
  try {
    const session = await readSession(request, env);
    if (!session) return json({ authenticated: false }, 200);
    return json({ authenticated: true, name: session.name }, 200);
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
