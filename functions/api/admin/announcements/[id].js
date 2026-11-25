// DELETE /api/admin/announcements/:id
// Removes one announcement. Admin session required.
import { json, readSession } from "../../../_utils/admin.js";
import {
  deleteAnnouncement,
  parseId,
  unauthorized,
} from "../../../_utils/bulletin.js";

export async function onRequestDelete({ request, env, params }) {
  try {
    if (!(await readSession(request, env))) return unauthorized();

    const id = parseId(params.id);
    if (id === null) return json({ error: "Bad announcement id." }, 400);

    const removed = await deleteAnnouncement(env, id);
    if (!removed) return json({ error: "No such announcement." }, 404);

    return json({ ok: true, removed: id });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
