// ============================================================
//  functions/api/me.js
//  GET /api/me
//
//  Answers exactly one question for the browser:
//      "who am I, and what is my role?"
//
//  index.html calls this on load and redirects accordingly.
//
//  IMPORTANT: this endpoint does NOT grant any access. It only
//  reports what the SERVER already decided. The real enforcement
//  is `requireAdmin(...)` inside each protected endpoint
//  (see api/admin/students.js). A user who fakes the redirect
//  here still gets a 403 from the endpoints that matter.
// ============================================================

import { requireUser, json } from "../_utils/auth.js";

export async function onRequestGet({ request, env }) {
  // 401 if there is no valid session cookie.
  const { user, error } = await requireUser(request, env);
  if (error) return error;

  // Return only what the UI needs. Never send the password hash.
  // `gmail` is included because the settings section shows it as the
  // current address -- it never leaves the user's own session.
  return json({
    user_id: user.user_id,
    name: user.name,
    gmail: user.gmail,
    access: user.access,
  });
}
