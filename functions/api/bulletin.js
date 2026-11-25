// GET /api/bulletin -- everything the bulletin board shows.
//
//   {
//     "announcements": [ { id, message, detail, createdAt }, ... ],
//     "events": {
//       "school": [ { id, kind, message, date, createdAt }, ... ],
//       "club":   [ ... ]
//     }
//   }
//
// Public: students read the board without logging in. Writing is
// admin-only, through /api/admin/announcements and /api/admin/events.
import { json } from "../_utils/admin.js";
import { listBulletin } from "../_utils/bulletin.js";

export async function onRequestGet({ env }) {
  try {
    return json(await listBulletin(env));
  } catch (err) {
    return json({ error: err.message }, 500);
  }
}
