// /api/admin/credentials
//
//   GET  -> { admins: [{ name, createdAt }], setupRequired }
//   POST -> create or replace one admin credential
//           Body: { "name": "david", "password": "abcd12345678" }
//
// The store is the admin_credentials table in the `witi_users` D1
// database; passwords are PBKDF2 hashes, never plaintext.
//
// Access rule:
//   * If the store is EMPTY, the first credential may be created
//     without a session -- otherwise nobody could ever bootstrap
//     the board. (This one gap is also why the site needs access
//     protection at the Cloudflare edge.)
//   * Otherwise a valid admin session cookie is required.
import {
  json,
  normalizeName,
  validatePassword,
  saveAdmin,
  listAdmins,
  getAdmin,
  readSession,
} from "../../_utils/admin.js";

async function requireAccess(request, env) {
  const admins = await listAdmins(env);
  const setupRequired = admins.length === 0;
  if (setupRequired) return { admins, setupRequired, session: null };

  const session = await readSession(request, env);
  if (!session) {
    return {
      error: json({ error: "Log in as an admin first." }, 401),
      admins,
      setupRequired,
    };
  }
  return { admins, setupRequired, session };
}

export async function onRequestGet({ request, env }) {
  try {
    const access = await requireAccess(request, env);
    if (access.error) return access.error;

    // Names and dates only. The password hashes never leave the
    // server, and there is nothing useful to show for them anyway.
    return json({
      setupRequired: access.setupRequired,
      admins: access.admins,
    });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}

export async function onRequestPost({ request, env }) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Send a JSON body." }, 400);
  }

  const nameResult = normalizeName(body?.name);
  if (nameResult.error) return json({ error: nameResult.error }, 400);

  const passwordResult = validatePassword(body?.password);
  if (passwordResult.error) return json({ error: passwordResult.error }, 400);

  try {
    const access = await requireAccess(request, env);
    if (access.error) return access.error;

    const existing = await getAdmin(env, nameResult.name);
    if (existing && !access.session) {
      return json(
        { error: "That admin already exists. Log in to change it." },
        409,
      );
    }

    const { replaced } = await saveAdmin(
      env,
      nameResult.name,
      passwordResult.password,
    );

    return json(
      {
        ok: true,
        replaced,
        name: nameResult.name,
        passwordLength: passwordResult.password.length,
        message: replaced
          ? `Password updated for ${nameResult.name}.`
          : `${nameResult.name} can now log in as an admin.`,
      },
      replaced ? 200 : 201,
    );
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
