// DELETE /api/admin/credentials/:name
// Removes one admin from the database. Requires a session, and
// refuses to remove the last remaining admin (that would leave the
// store empty and open first-run setup to anyone).
import {
  json,
  normalizeName,
  listAdmins,
  getAdmin,
  deleteAdmin,
  readSession,
} from "../../../_utils/admin.js";

export async function onRequestDelete({ request, env, params }) {
  try {
    const session = await readSession(request, env);
    if (!session) return json({ error: "Log in as an admin first." }, 401);

    const nameResult = normalizeName(
      Array.isArray(params.name) ? params.name.join("/") : params.name,
    );
    if (nameResult.error) return json({ error: nameResult.error }, 400);

    const record = await getAdmin(env, nameResult.name);
    if (!record) return json({ error: "No such admin." }, 404);

    const admins = await listAdmins(env);
    if (admins.length <= 1) {
      return json({ error: "You cannot remove the last admin." }, 409);
    }

    // admin_sessions rows go with it (ON DELETE CASCADE).
    await deleteAdmin(env, record.admin_id);
    return json({ ok: true, removed: record.name });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
