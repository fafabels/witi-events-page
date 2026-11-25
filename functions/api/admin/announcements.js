// /api/admin/announcements
//
//   GET  -> { announcements: [...] }        (admin session required)
//   POST -> body { "message": "...", "detail": "..." }
//           -> 201 { announcement }
//
// `message` is the short line shown on the board; `detail` is the
// longer text bulletin.html reveals on hover / click / focus.
import { json, readSession } from "../../_utils/admin.js";
import {
  validateAnnouncement,
  listAnnouncements,
  addAnnouncement,
  unauthorized,
} from "../../_utils/bulletin.js";

export async function onRequestGet({ request, env }) {
  try {
    if (!(await readSession(request, env))) return unauthorized();
    return json({ announcements: await listAnnouncements(env) });
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

  const result = validateAnnouncement(body);
  if (result.error) return json({ error: result.error }, 400);

  try {
    if (!(await readSession(request, env))) return unauthorized();

    const announcement = await addAnnouncement(env, result);
    return json(
      {
        ok: true,
        announcement,
        message: "Announcement posted.",
      },
      201,
    );
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
