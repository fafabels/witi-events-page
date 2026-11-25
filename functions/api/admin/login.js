// POST /api/admin/login
// Body: { "name": "david", "password": "abcd12345678" }
//
// Checks the name/password against the WITI_ADMINS KV store.
// On success it sets an HttpOnly session cookie and returns the
// admin's name; the browser never sees the password again.
import {
  json,
  normalizeName,
  validatePassword,
  getAdmin,
  verifyPassword,
  createSession,
  sessionCookie,
  listAdmins,
} from "../../_utils/admin.js";

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Send a JSON body." }, 400);
  }

  const nameResult = normalizeName(body?.name);
  if (nameResult.error) return json({ error: nameResult.error }, 400);

  // Length is checked too, but login should not hint at the real
  // password length beyond what the form already says.
  const password = String(body?.password ?? "");

  let record = null;
  try {
    record = await getAdmin(env, nameResult.name);
  } catch (err) {
    return json({ error: err.message }, 500);
  }

  const ok = record ? await verifyPassword(password, record.password) : false;

  if (!ok) {
    // Same message for "no such name" and "wrong password" so the
    // form cannot be used to discover which admin names exist.
    return json({ error: "That name and password do not match." }, 401);
  }

  const { token, maxAge } = await createSession(env, record.name);
  return json({ ok: true, name: record.name }, 200, {
    "set-cookie": sessionCookie(request, token, maxAge),
  });
}

// GET /api/admin/login -> small helper for the login page: is the
// store still empty (first-run setup) and is anyone logged in?
export async function onRequestGet({ request, env }) {
  try {
    const admins = await listAdmins(env);
    return json({ setupRequired: admins.length === 0 });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
