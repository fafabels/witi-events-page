// ============================================================
//  functions/api/me.js
//  GET /api/me
//
//  Answers two questions for the browser:
//      "who am I, and what is my role?"
//      "is the site in strict (student-only) mode?"
//
//  index.html and the user pages call this on load and route
//  accordingly. The security switch on the admin page is the source of
//  `strict`, read through functions/_utils/settings.js.
//
//  IMPORTANT: this endpoint does NOT grant any access. It only
//  reports what the SERVER already decided. The real enforcement
//  is `requireAdmin(...)` inside each protected endpoint
//  (see api/admin/students.js) and the mode check inside
//  api/auth/signup.js and api/auth/login.js. A user who fakes the
//  redirect here still gets a 403 from the endpoints that matter.
//
//  In open mode (strict = false) there is nobody to log in, so this
//  answers 200 with `access: null` instead of 401. Pages use that to
//  show the board without a session. It reveals nothing: an anonymous
//  visitor gets exactly the same body, which is why /api/bulletin is
//  public in that mode anyway.
// ============================================================

import { requireUser, json } from "../_utils/auth.js";
import { isStrictMode, entryPage } from "../_utils/settings.js";

export async function onRequestGet({ request, env }) {
  const strict = await isStrictMode(env);

  // 401 if there is no valid session cookie.
  const { user, error } = await requireUser(request, env);

  if (error) {
    if (strict) return error; // strict mode: "not logged in" is a 401
    return json({
      strict: false,
      access: null,
      entry: entryPage(false),
    });
  }

  // Return only what the UI needs. Never send the password hash.
  // `gmail` is included because the settings section shows it as the
  // current address -- it never leaves the user's own session.
  return json({
    strict,
    user_id: user.user_id,
    name: user.name,
    gmail: user.gmail,
    access: user.access,
    entry: entryPage(strict),
  });
}
