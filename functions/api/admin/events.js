// /api/admin/events
//
// GET  -> { events: { school: [...], club: [...] }, today }
//         Unlike /api/bulletin this INCLUDES past events, flagged
//         `past: true`, so a postponed one can still be removed.
// POST -> body { "kind": "school"|"club", "message": "...", "date": "YYYY-MM-DD" }
//           -> 201 { event }
//
// `kind` decides which board the event lands on in bulletin.html,
// and `date` comes straight from the admin page's date input.
import { json, readSession } from "../../_utils/admin.js";
import {
  validateEvent,
  listEvents,
  addEvent,
  todayIso,
  unauthorized,
} from "../../_utils/bulletin.js";

export async function onRequestGet({ request, env }) {
  try {
    if (!(await readSession(request, env))) return unauthorized();
    const events = await listEvents(env, null, { includePast: true });
    return json({
      today: todayIso(),
      events: {
        school: events.filter((event) => event.kind === "school"),
        club: events.filter((event) => event.kind === "club"),
      },
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

  const result = validateEvent(body);
  if (result.error) return json({ error: result.error }, 400);

  try {
    if (!(await readSession(request, env))) return unauthorized();

    const event = await addEvent(env, result);
    return json({ ok: true, event, message: "Event posted." }, 201);
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
