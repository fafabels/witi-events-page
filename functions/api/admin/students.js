// ============================================================
//  functions/api/admin/students.js
//  Admin-only endpoint for the student master list.
//
//    GET  /api/admin/students   -> list the roster
//    POST /api/admin/students   -> add one student  { student_id, name }
//
//  Deployed automatically by Cloudflare Pages (functions/ routing).
//  Uses the D1 binding named "witi_users" from wrangler.toml.
//
//  Role checks live in functions/_utils/auth.js -- one shared
//  definition of "is this an admin", used by every endpoint.
// ============================================================

import { requireAdmin, json } from "../../_utils/auth.js";

// --- Strict student-id template ---------------------------------
//   SJ, batch year, a dash, then 4 digits  ->  SJ23-0001
//   Same format as schema.sql and signup.html.
const STUDENT_ID_PATTERN = /^SJ\d{2}-\d{4}$/;

// One place to validate & normalise, so every caller behaves the same.
function normalizeStudentId(raw) {
  const value = String(raw ?? "").trim();
  if (!STUDENT_ID_PATTERN.test(value)) {
    return {
      ok: false,
      error: "Student ID must look like SJ23-0001 (SJ, batch year, dash, 4 digits).",
    };
  }
  return { ok: true, value };
}

function normalizeName(raw) {
  const value = String(raw ?? "")
    .trim()
    .replace(/\s+/g, " ");
  if (value.length < 2 || value.length > 100) {
    return { ok: false, error: "Name must be between 2 and 100 characters." };
  }
  return { ok: true, value };
}

// Shared getCurrentUser / isAdmin / requireAdmin / json live in
// functions/_utils/auth.js -- imported above.

// --- Handlers ---------------------------------------------------
export async function onRequestGet({ request, env }) {
  // 1. AuthN + AuthZ -- only admins may read the roster.
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  const { results } = await env.witi_users
    .prepare(
      "SELECT student_id, name FROM student_master_list ORDER BY student_id",
    )
    .all();

  return json({ students: results });
}

export async function onRequestPost({ request, env }) {
  // 1. AuthN + AuthZ -- only admins may add to the roster.
  const { error } = await requireAdmin(request, env);
  if (error) return error;

  // 2. Read + validate the body.
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body." }, 400);
  }

  const id = normalizeStudentId(body.student_id);
  if (!id.ok) return json({ error: id.error }, 422);

  const name = normalizeName(body.name);
  if (!name.ok) return json({ error: name.error }, 422);

  // 3. Insert. "INSERT OR IGNORE" makes re-adding a student harmless.
  const result = await env.witi_users
    .prepare(
      "INSERT OR IGNORE INTO student_master_list (student_id, name) VALUES (?, ?)",
    )
    .bind(id.value, name.value)
    .run();

  if (result.meta.changes === 0) {
    return json(
      { error: `Student ID ${id.value} is already on the list.` },
      409,
    );
  }

  return json(
    { ok: true, student: { student_id: id.value, name: name.value } },
    201,
  );
}
