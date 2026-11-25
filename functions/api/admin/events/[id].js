// DELETE /api/admin/events/:id
// Removes one event. Admin session required.
import { json, readSession } from "../../../_utils/admin.js";
import {
  deleteEvent,
  parseId,
  unauthorized,
} from "../../../_utils/bulletin.js";

export async function onRequestDelete({ request, env, params }) {
  try {
    if (!(await readSession(request, env))) return unauthorized();

    const id = parseId(params.id);
    if (id === null) return json({ error: "Bad event id." }, 400);

    const removed = await deleteEvent(env, id);
    if (!removed) return json({ error: "No such event." }, 404);

    return json({ ok: true, removed: id });
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
