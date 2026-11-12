const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const sql = neon(process.env.DATABASE_URL);
const STAFF_SESSION_HOURS = 12;
const YOUTH_SESSION_HOURS = 8;
const MAX_FAILED_LOGINS = 5;
const LOCK_MINUTES = 15;
const MAX_STATE_BYTES = 200 * 1024;

let schemaReady = null;
function ensureSchema() {
  if (!schemaReady) {
    const ddl = fs.readFileSync(path.join(__dirname, '..', '..', 'db', 'schema.sql'), 'utf8');
    schemaReady = (async () => {
      const statements = ddl.replace(/--.*$/gm, '').split(';').map(s => s.trim()).filter(Boolean);
      for (const st of statements) await sql(st);
    })().catch(err => { schemaReady = null; throw err; });
  }
  return schemaReady;
}

function json(status, body) {
  return { statusCode: status, headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }, body: JSON.stringify(body) };
}

function hashSecret(secret) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return `scrypt$${salt}$${hash}`;
}
function checkSecret(secret, stored) {
  const [kind, salt, hash] = String(stored || '').split('$');
  if (kind !== 'scrypt') return false;
  const test = crypto.scryptSync(String(secret), salt, 64);
  const want = Buffer.from(hash, 'hex');
  return want.length === test.length && crypto.timingSafeEqual(want, test);
}
const sha256 = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', process.env.STAFF_SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}
function verify(token) {
  const [body, sig] = String(token || '').split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', process.env.STAFF_SESSION_SECRET).update(body).digest('base64url');
  if (sig.length !== expect.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expect))) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    if (!payload.exp || Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}
function bearer(event) {
  const auth = event.headers.authorization || event.headers.Authorization || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : '';
}

async function currentStaff(event) {
  const p = verify(bearer(event));
  if (!p || !p.sid) return null;
  const rows = await sql`SELECT id, email, name, role FROM staff WHERE id = ${p.sid}`;
  return rows[0] || null;
}
async function currentYouth(event) {
  const p = verify(bearer(event));
  if (!p || !p.yid) return null;
  const rows = await sql`SELECT id, first_name, last_name, site, status, app_state FROM youth WHERE id = ${p.yid}`;
  return rows[0] || null;
}

async function audit(staffId, action, target) {
  await sql`INSERT INTO audit_log (staff_id, action, target) VALUES (${staffId}, ${action}, ${target})`;
}
function parseBody(event) {
  try { return event.body ? JSON.parse(event.body) : {}; } catch { return null; }
}
const cleanName = (s) => String(s || '').trim().replace(/\s+/g, ' ').slice(0, 60);
const validEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(String(e || '').trim());
function siteBase(event) {
  const host = event.headers['x-forwarded-host'] || event.headers.host || '';
  return host ? `https://${host}` : '';
}
function newWaiverToken() {
  const token = crypto.randomBytes(24).toString('base64url');
  return { token, hash: sha256(token) };
}
function validAge(a) {
  const n = Number(a);
  return Number.isInteger(n) && n >= 13 && n <= 19 ? n : null;
}
function validPhone(p) {
  const text = String(p || '').trim();
  const digits = text.replace(/\D/g, '');
  return digits.length >= 10 && digits.length <= 15 && text.length <= 30 ? text : null;
}
function partnerView(y) {
  const jobs = ((y.app_state && y.app_state.jobInterests) || []).map(i => ({
    title: i.title || 'A partner job', business: i.business || null, status: i.status || ''
  }));
  return { id: y.id, firstName: y.first_name, lastName: y.last_name, site: y.site, jobs };
}
async function youthAccess(staff, youthId) {
  if (staff.role === 'admin') return true;
  if (staff.role === 'staff') {
    const r = await sql`SELECT 1 FROM staff_youth WHERE staff_id = ${staff.id} AND youth_id = ${youthId}`;
    return r.length > 0;
  }
  if (staff.role === 'partner') {
    const r = await sql`SELECT 1 FROM staff_youth WHERE staff_id = ${staff.id} AND youth_id = ${youthId} AND guardian_consent_at IS NOT NULL`;
    return r.length > 0;
  }
  return false;
}
function youthPublic(y) {
  return { id: y.id, firstName: y.first_name, lastName: y.last_name, site: y.site, status: y.status };
}
function lessonsFromState(state) {
  const done = [];
  const prog = (state && state.progress) || {};
  for (let i = 1; i <= 8; i++) if (prog['m' + i] && prog['m' + i].done) done.push(i);
  return done;
}

exports.handler = async (event) => {
  const route = (event.path || '').replace(/^.*\/api/, '').replace(/\/+$/, '') || '/';
  const method = event.httpMethod;

  if (route === '/health' && method === 'GET') {
    try {
      await sql`SELECT 1 AS ok`;
      await ensureSchema();
      return json(200, { ok: true, database: 'connected' });
    } catch (err) {
      console.error(err);
      return json(500, { ok: false, error: 'Database is not reachable' });
    }
  }

  try {
    await ensureSchema();
    const body = parseBody(event);
    if (body === null) return json(400, { error: 'Invalid JSON' });

    /* ---------- Staff: setup and login ---------- */
    if (route === '/setup' && method === 'POST') {
      const count = (await sql`SELECT count(*)::int AS n FROM staff`)[0].n;
      if (count > 0) return json(404, { error: 'Not found' });
      if (!process.env.SETUP_CODE) return json(403, { error: 'SETUP_CODE is not set on the server.' });
      if (String(body.setupCode || '').trim() !== process.env.SETUP_CODE.trim()) return json(403, { error: 'Setup code is wrong' });
      if (!body.email || !body.name || !body.password || body.password.length < 12) return json(400, { error: 'Name, email, and a password of at least 12 characters are required' });
      const rows = await sql`INSERT INTO staff (email, name, pass_hash, role) VALUES (${body.email.toLowerCase()}, ${body.name}, ${hashSecret(body.password)}, 'admin') RETURNING id, email, name, role`;
      await audit(rows[0].id, 'setup_admin', rows[0].email);
      return json(201, { staff: rows[0] });
    }

    if (route === '/login' && method === 'POST') {
      const rows = await sql`SELECT id, email, name, role, pass_hash FROM staff WHERE email = ${String(body.email || '').toLowerCase()}`;
      const s = rows[0];
      if (!s || !checkSecret(body.password || '', s.pass_hash)) return json(401, { error: 'Email or password is wrong' });
      const token = sign({ sid: s.id, exp: Date.now() + STAFF_SESSION_HOURS * 3600 * 1000 });
      await audit(s.id, 'login', s.email);
      return json(200, { token, staff: { id: s.id, email: s.email, name: s.name, role: s.role } });
    }

    /* ---------- Students: sign up, sign in, save progress ---------- */
    if (route === '/student/signup' && method === 'POST') {
      const first = cleanName(body.firstName), last = cleanName(body.lastName);
      const site = body.site, pin = String(body.pin || ''), gEmail = String(body.guardianEmail || '').trim().toLowerCase();
      const age = validAge(body.age), gPhone = validPhone(body.guardianPhone);
      if (!first || last.length < 2) return json(400, { error: 'Type your first name and your full last name.' });
      if (!['jdc', 'stars'].includes(site)) return json(400, { error: 'Pick where you are.' });
      if (!age) return json(400, { error: 'Pick your age.' });
      if (!/^\d{4}$/.test(pin)) return json(400, { error: 'Your PIN needs exactly 4 numbers.' });
      if (!validEmail(gEmail)) return json(400, { error: "Type your parent or guardian's email address." });
      if (!gPhone) return json(400, { error: "Type your parent or guardian's phone number." });
      const dup = await sql`SELECT id FROM youth WHERE lower(first_name) = lower(${first}) AND lower(last_name) = lower(${last}) LIMIT 1`;
      if (dup.length) return json(409, { error: "You're already signed up. Sign in with your PIN instead." });
      const w = newWaiverToken();
      const rows = await sql`
        INSERT INTO youth (first_name, last_name, site, pin_hash, consent_on_file, guardian_email, guardian_phone, status, waiver_token_hash, intake)
        VALUES (${first}, ${last}, ${site}, ${hashSecret(pin)}, false, ${gEmail}, ${gPhone}, 'pending', ${w.hash}, ${JSON.stringify({ age })}::jsonb)
        RETURNING id, first_name, last_name, site, status`;
      const y = rows[0];
      await audit(null, 'student_signup', y.id);
      const token = sign({ yid: y.id, exp: Date.now() + YOUTH_SESSION_HOURS * 3600 * 1000 });
      return json(201, { token, youth: youthPublic(y), state: {} });
    }

    if (route === '/student/login' && method === 'POST') {
      const first = cleanName(body.firstName), last = cleanName(body.lastName), pin = String(body.pin || '');
      const rows = await sql`SELECT id, first_name, last_name, site, status, pin_hash, app_state, failed_logins, locked_until
        FROM youth WHERE lower(first_name) = lower(${first}) AND lower(last_name) = lower(${last})`;
      if (!rows.length) return json(401, { error: "That name and PIN don't match. Check the spelling or ask staff." });
      const now = Date.now();
      const open = rows.filter(r => !r.locked_until || new Date(r.locked_until).getTime() < now);
      if (!open.length) return json(429, { error: 'Too many tries. Wait 15 minutes or ask staff to help.' });
      const match = open.find(r => checkSecret(pin, r.pin_hash));
      if (!match) {
        for (const r of open) {
          const fails = r.failed_logins + 1;
          if (fails >= MAX_FAILED_LOGINS) {
            await sql`UPDATE youth SET failed_logins = 0, locked_until = now() + make_interval(mins => ${LOCK_MINUTES}::int) WHERE id = ${r.id}`;
          } else {
            await sql`UPDATE youth SET failed_logins = ${fails} WHERE id = ${r.id}`;
          }
        }
        return json(401, { error: "That name and PIN don't match. Check the spelling or ask staff." });
      }
      await sql`UPDATE youth SET failed_logins = 0, locked_until = NULL WHERE id = ${match.id}`;
      const token = sign({ yid: match.id, exp: Date.now() + YOUTH_SESSION_HOURS * 3600 * 1000 });
      return json(200, { token, youth: youthPublic(match), state: match.app_state || {} });
    }

    if (route === '/student/me' && (method === 'GET' || method === 'PUT')) {
      const y = await currentYouth(event);
      if (!y) return json(401, { error: 'Sign in again.' });
      if (method === 'GET') return json(200, { youth: youthPublic(y), state: y.app_state || {} });
      const state = { progress: body.progress || {}, plan: body.plan || {}, intake: body.intake || {}, jobInterests: Array.isArray(body.jobInterests) ? body.jobInterests.slice(0, 100) : [] };
      const raw = JSON.stringify(state);
      if (Buffer.byteLength(raw) > MAX_STATE_BYTES) return json(413, { error: 'Too much data to save.' });
      await sql`UPDATE youth SET app_state = ${raw}::jsonb, updated_at = now() WHERE id = ${y.id}`;
      for (const n of lessonsFromState(state)) {
        await sql`INSERT INTO lesson_progress (youth_id, lesson) VALUES (${y.id}, ${n}) ON CONFLICT DO NOTHING`;
      }
      return json(200, { ok: true, status: y.status });
    }

    /* ---------- God's Sons sign-up (public invite link) ---------- */
    if (route === '/gs/signup' && method === 'POST') {
      if (String(body.website || '').trim()) return json(201, { ok: true });
      const t = (v, n) => String(v || '').trim().replace(/\s+/g, ' ').slice(0, n);
      const pName = cleanName(body.parentName), pRel = t(body.parentRelation, 40), pPhone = validPhone(body.parentPhone);
      const pEmail = t(body.parentEmail, 120).toLowerCase();
      const kFirst = cleanName(body.kidFirst), kLast = cleanName(body.kidLast);
      const age = Number(body.kidAge);
      if (pName.length < 2) return json(400, { error: 'Type your full name.' });
      if (!pRel) return json(400, { error: 'Choose how you are related to your son.' });
      if (!pPhone) return json(400, { error: 'Type a phone number we can reach you at.' });
      if (pEmail && !validEmail(pEmail)) return json(400, { error: 'Check the email address.' });
      if (!kFirst || kLast.length < 2) return json(400, { error: "Type your son's first and last name." });
      if (!Number.isInteger(age) || age < 6 || age > 19) return json(400, { error: "Choose your son's age." });
      if (body.consentProgram !== true) return json(400, { error: 'Check the box giving permission for your son to join God\'s Sons.' });
      const SIZES = ['YS', 'YM', 'YL', 'AS', 'AM', 'AL', 'AXL', 'A2XL', 'A3XL'];
      const INTS = ['Football', 'Basketball', 'Baseball', 'Track', 'Soccer', 'Other sports', 'Music', 'Art', 'Tech and coding', 'Gaming', 'Cars', 'Cooking', 'Outdoors', 'Business', 'Church and faith'];
      const interests = (Array.isArray(body.interests) ? body.interests : []).filter(i => INTS.includes(i));
      const dup = await sql`SELECT id FROM gs_signups WHERE lower(kid_first) = lower(${kFirst}) AND lower(kid_last) = lower(${kLast}) AND parent_phone = ${pPhone} LIMIT 1`;
      if (dup.length) return json(200, { ok: true, already: true });
      const rows = await sql`INSERT INTO gs_signups (parent_name, parent_relation, parent_phone, parent_email, contact_pref, kid_first, kid_last, kid_age,
          kid_grade, kid_school, shirt_size, interests, favorite_team, food_notes, transport, goals, consent_program, consent_messages, media_ok, ref)
        VALUES (${pName}, ${pRel}, ${pPhone}, ${pEmail || null}, ${['text', 'call', 'email'].includes(body.contactPref) ? body.contactPref : 'text'},
          ${kFirst}, ${kLast}, ${age}, ${t(body.kidGrade, 20) || null}, ${t(body.kidSchool, 80) || null},
          ${SIZES.includes(body.shirtSize) ? body.shirtSize : null}, ${JSON.stringify(interests)}::jsonb, ${t(body.favoriteTeam, 80) || null},
          ${t(body.foodNotes, 200) || null}, ${t(body.transport, 40) || null}, ${t(body.goals, 400) || null},
          true, ${body.consentMessages === true}, ${body.mediaOk === true}, ${t(body.ref, 40) || null})
        RETURNING id`;
      await audit(null, 'gs_signup', rows[0].id);
      return json(201, { ok: true });
    }

    /* ---------- Guardian waiver (public, token-gated) ---------- */
    const wm = route.match(/^\/waiver\/([A-Za-z0-9_-]{20,64})$/);
    if (wm) {
      const hash = sha256(wm[1]);
      const rows = await sql`SELECT id, first_name, site, status FROM youth WHERE waiver_token_hash = ${hash}`;
      const y = rows[0];
      if (!y) return json(404, { error: 'This link is not valid or was already used. Ask Ivy Foundation staff for a new one.' });
      if (method === 'GET') return json(200, { firstName: y.first_name, site: y.site, status: y.status });
      if (method === 'POST') {
        const signer = cleanName(body.signerName), relation = cleanName(body.relation);
        if (!signer || signer.length < 3) return json(400, { error: 'Type your full name as your signature.' });
        if (!relation) return json(400, { error: 'Tell us your relationship to the student.' });
        if (body.agree !== true) return json(400, { error: 'Check the box to agree.' });
        await sql`UPDATE youth SET status = 'active', consent_on_file = true, consent_date = CURRENT_DATE,
          guardian_name = ${signer}, guardian_relation = ${relation}, waiver_signer = ${signer}, waiver_relation = ${relation},
          waiver_signed_at = now(), waiver_method = 'online', waiver_token_hash = NULL, updated_at = now() WHERE id = ${y.id}`;
        await audit(null, 'waiver_signed_online', y.id);
        return json(200, { ok: true });
      }
    }

    /* ---------- Staff-only routes ---------- */
    const staff = await currentStaff(event);
    if (!staff) return json(401, { error: 'Sign in first' });

    if (route === '/me' && method === 'GET') return json(200, { staff });

    if (route === '/gs/signups' && method === 'GET') {
      if (staff.role !== 'admin') return json(403, { error: "Only an admin can see God's Sons sign-ups" });
      const rows = await sql`SELECT * FROM gs_signups ORDER BY created_at DESC LIMIT 1000`;
      await audit(staff.id, 'view_gs_signups', String(rows.length));
      return json(200, { signups: rows });
    }

    if (route === '/gs/status' && method === 'POST') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can update sign-ups' });
      if (!/^[0-9a-f-]{36}$/.test(String(body.id || '')) || !['new', 'contacted', 'active', 'inactive'].includes(body.status)) return json(400, { error: 'Invalid update' });
      await sql`UPDATE gs_signups SET status = ${body.status} WHERE id = ${body.id}`;
      return json(200, { ok: true });
    }

    if (route === '/grants' && method === 'GET') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can see the grant calendar' });
      return json(200, require('../grants.json'));
    }

    if (route === '/staff' && method === 'GET') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can see the staff list' });
      const rows = await sql`SELECT id, name, email, role, created_at FROM staff ORDER BY role, name`;
      return json(200, { staff: rows });
    }

    if (route === '/assignments' && method === 'GET') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can manage assignments' });
      const rows = await sql`SELECT a.staff_id, a.youth_id, a.guardian_consent_at, a.guardian_consent_by,
          s.name AS staff_name, s.role, y.first_name, y.last_name
        FROM staff_youth a JOIN staff s ON s.id = a.staff_id JOIN youth y ON y.id = a.youth_id
        ORDER BY y.last_name, y.first_name, s.name`;
      return json(200, { assignments: rows });
    }

    if (route === '/assignments' && method === 'POST') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can manage assignments' });
      const uuid = /^[0-9a-f-]{36}$/;
      if (!uuid.test(String(body.staffId || '')) || !uuid.test(String(body.youthId || ''))) return json(400, { error: 'Choose a mentor or partner and a youth.' });
      const target = await sql`SELECT id, role FROM staff WHERE id = ${body.staffId}`;
      if (!target.length || target[0].role === 'admin') return json(400, { error: 'Choose a mentor or partner.' });
      const y = await sql`SELECT id FROM youth WHERE id = ${body.youthId}`;
      if (!y.length) return json(400, { error: 'Choose a youth.' });
      let consentAt = null, consentBy = null;
      if (target[0].role === 'partner') {
        const gName = cleanName(body.guardianName);
        if (body.guardianConsent !== true || !gName) {
          return json(400, { error: "A partner sees a youth's job track only after the guardian signs consent. Check the box and enter the guardian's name." });
        }
        consentAt = new Date().toISOString();
        consentBy = gName;
      }
      await sql`INSERT INTO staff_youth (staff_id, youth_id, guardian_consent_at, guardian_consent_by)
        VALUES (${target[0].id}, ${y[0].id}, ${consentAt}, ${consentBy})
        ON CONFLICT (staff_id, youth_id) DO UPDATE SET guardian_consent_at = EXCLUDED.guardian_consent_at, guardian_consent_by = EXCLUDED.guardian_consent_by`;
      await audit(staff.id, 'assign_youth', `${target[0].id}:${y[0].id}`);
      return json(201, { ok: true });
    }

    if (route === '/assignments' && method === 'DELETE') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can manage assignments' });
      const uuid = /^[0-9a-f-]{36}$/;
      if (!uuid.test(String(body.staffId || '')) || !uuid.test(String(body.youthId || ''))) return json(400, { error: 'Invalid assignment.' });
      await sql`DELETE FROM staff_youth WHERE staff_id = ${body.staffId} AND youth_id = ${body.youthId}`;
      await audit(staff.id, 'unassign_youth', `${body.staffId}:${body.youthId}`);
      return json(200, { ok: true });
    }

    if (route === '/staff' && method === 'POST') {
      if (staff.role !== 'admin') return json(403, { error: 'Only an admin can add staff' });
      const name = cleanName(body.name);
      const email = String(body.email || '').trim().toLowerCase();
      const role = ['admin', 'staff', 'partner'].includes(body.role) ? body.role : 'staff';
      if (!name || name.length < 2) return json(400, { error: "Type the person's full name." });
      if (!validEmail(email)) return json(400, { error: 'Type a valid email address.' });
      if (String(body.password || '').length < 12) return json(400, { error: 'The temporary password needs at least 12 characters.' });
      try {
        const rows = await sql`INSERT INTO staff (email, name, pass_hash, role) VALUES (${email}, ${name}, ${hashSecret(body.password)}, ${role})
          RETURNING id, email, name, role, created_at`;
        await audit(staff.id, 'create_staff', rows[0].email);
        return json(201, { staff: rows[0] });
      } catch (err) {
        if (err && err.code === '23505') return json(409, { error: 'That email already has an account.' });
        throw err;
      }
    }

    if (route === '/youth' && method === 'GET' && staff.role === 'partner') {
      const rows = await sql`SELECT y.id, y.first_name, y.last_name, y.site, y.app_state
        FROM youth y JOIN staff_youth a ON a.youth_id = y.id
        WHERE a.staff_id = ${staff.id} AND a.guardian_consent_at IS NOT NULL
        ORDER BY y.last_name, y.first_name`;
      return json(200, { youth: rows.map(partnerView) });
    }

    if (route === '/youth' && method === 'GET' && staff.role === 'staff') {
      const rows = await sql`
        SELECT y.id, y.first_name, y.last_name, y.site, y.status, y.consent_on_file, y.consent_date, y.guardian_email, y.created_at,
          (SELECT count(*)::int FROM lesson_progress p WHERE p.youth_id = y.id) AS lessons_done,
          (SELECT max(v.visited_at) FROM mentor_visits v WHERE v.youth_id = y.id) AS last_visit
        FROM youth y JOIN staff_youth a ON a.youth_id = y.id AND a.staff_id = ${staff.id}
        ORDER BY y.last_name, y.first_name`;
      return json(200, { youth: rows });
    }

    if (route === '/youth' && method === 'GET' && staff.role === 'admin') {
      const rows = await sql`
        SELECT y.id, y.first_name, y.last_name, y.site, y.status, y.consent_on_file, y.consent_date, y.guardian_email, y.created_at,
          (SELECT count(*)::int FROM lesson_progress p WHERE p.youth_id = y.id) AS lessons_done,
          (SELECT max(v.visited_at) FROM mentor_visits v WHERE v.youth_id = y.id) AS last_visit
        FROM youth y ORDER BY y.last_name, y.first_name`;
      return json(200, { youth: rows });
    }

    if (route === '/youth' && method === 'POST') {
      if (staff.role === 'partner') return json(403, { error: 'Partners have read-only access' });
      if (!body.firstName || !body.lastName || !['jdc', 'stars'].includes(body.site)) return json(400, { error: 'First name, last name, and site (jdc or stars) are required' });
      if (!body.consentOnFile || !body.guardianName || !body.guardianRelation) return json(400, { error: 'Guardian permission must be on file before an account is created' });
      if (!/^\d{4}$/.test(String(body.pin || ''))) return json(400, { error: 'PIN must be 4 digits' });
      const age = validAge(body.age), gPhone = validPhone(body.guardianPhone);
      if (!age) return json(400, { error: 'Pick the youth age (13 to 19).' });
      if (!gPhone) return json(400, { error: "Type the guardian's phone number." });
      const rows = await sql`
        INSERT INTO youth (first_name, last_name, site, pin_hash, consent_on_file, consent_date, guardian_name, guardian_relation, guardian_phone, guardian_email, status, waiver_method, interests, intake)
        VALUES (${cleanName(body.firstName)}, ${cleanName(body.lastName)}, ${body.site}, ${hashSecret(body.pin)}, true, ${body.consentDate || new Date().toISOString().slice(0, 10)},
                ${body.guardianName}, ${body.guardianRelation}, ${gPhone}, ${body.guardianEmail || null}, 'active', 'paper',
                ${JSON.stringify(body.interests || [])}::jsonb, ${JSON.stringify({ ...(body.intake || {}), age })}::jsonb)
        RETURNING id, first_name, last_name, site, status, consent_on_file, consent_date`;
      if (staff.role === 'staff') {
        await sql`INSERT INTO staff_youth (staff_id, youth_id) VALUES (${staff.id}, ${rows[0].id}) ON CONFLICT DO NOTHING`;
      }
      await audit(staff.id, 'create_youth', rows[0].id);
      return json(201, { youth: rows[0] });
    }

    const m = route.match(/^\/youth\/([0-9a-f-]{36})(\/[a-z-]+)?$/);
    if (m) {
      const id = m[1];
      const action = m[2] || '';
      if (!(await youthAccess(staff, id))) return json(404, { error: 'Not found' });
      if (staff.role === 'partner') {
        if (action === '' && method === 'GET') {
          const rows = await sql`SELECT id, first_name, last_name, site, app_state FROM youth WHERE id = ${id}`;
          await audit(staff.id, 'view_job_track', id);
          return json(200, { youth: partnerView(rows[0]) });
        }
        return json(403, { error: 'Partners have read-only access' });
      }
      if (action === '' && method === 'GET') {
        const rows = await sql`SELECT id, first_name, last_name, site, status, consent_on_file, consent_date, guardian_name, guardian_relation,
          guardian_phone, guardian_email, waiver_signed_at, waiver_signer, waiver_relation, waiver_method, app_state, created_at, updated_at FROM youth WHERE id = ${id}`;
        if (!rows.length) return json(404, { error: 'Not found' });
        const lessons = await sql`SELECT lesson, completed_at FROM lesson_progress WHERE youth_id = ${id} ORDER BY lesson`;
        const visits = await sql`SELECT v.visited_at, v.notes, s.name AS staff_name FROM mentor_visits v LEFT JOIN staff s ON s.id = v.staff_id WHERE v.youth_id = ${id} ORDER BY v.visited_at DESC`;
        await audit(staff.id, 'view_youth', id);
        return json(200, { youth: rows[0], lessons, visits });
      }
      if (action === '' && method === 'DELETE') {
        if (staff.role !== 'admin') return json(403, { error: 'Only an admin can delete a record' });
        await sql`DELETE FROM youth WHERE id = ${id}`;
        await audit(staff.id, 'delete_youth', id);
        return json(200, { deleted: id });
      }
      if (action === '/lesson' && method === 'POST') {
        const lesson = Number(body.lesson);
        if (!(lesson >= 1 && lesson <= 8)) return json(400, { error: 'Lesson must be 1 to 8' });
        await sql`INSERT INTO lesson_progress (youth_id, lesson) VALUES (${id}, ${lesson}) ON CONFLICT DO NOTHING`;
        await audit(staff.id, 'lesson_done', `${id}:${lesson}`);
        return json(200, { ok: true });
      }
      if (action === '/visit' && method === 'POST') {
        const rows = await sql`INSERT INTO mentor_visits (youth_id, staff_id, notes) VALUES (${id}, ${staff.id}, ${body.notes || null}) RETURNING id, visited_at`;
        await audit(staff.id, 'mentor_visit', id);
        return json(201, { visit: rows[0] });
      }
      if (action === '/waiver-link' && method === 'POST') {
        const rows = await sql`SELECT status FROM youth WHERE id = ${id}`;
        if (!rows.length) return json(404, { error: 'Not found' });
        if (rows[0].status === 'active') return json(400, { error: 'The waiver is already signed.' });
        const w = newWaiverToken();
        await sql`UPDATE youth SET waiver_token_hash = ${w.hash} WHERE id = ${id}`;
        await audit(staff.id, 'waiver_link', id);
        return json(200, { link: `${siteBase(event)}/waiver.html?t=${w.token}` });
      }
      if (action === '/paper-waiver' && method === 'POST') {
        if (staff.role !== 'admin') return json(403, { error: 'Only an admin can record a paper waiver' });
        const signer = cleanName(body.signerName), relation = cleanName(body.relation);
        if (!signer || !relation) return json(400, { error: "Enter the guardian's name and relationship from the paper form." });
        await sql`UPDATE youth SET status = 'active', consent_on_file = true, consent_date = CURRENT_DATE, guardian_name = ${signer}, guardian_relation = ${relation},
          waiver_signer = ${signer}, waiver_relation = ${relation}, waiver_signed_at = now(), waiver_method = 'paper', waiver_token_hash = NULL, updated_at = now() WHERE id = ${id}`;
        await audit(staff.id, 'paper_waiver', id);
        return json(200, { ok: true });
      }
      if (action === '/reset-pin' && method === 'POST') {
        if (!/^\d{4}$/.test(String(body.pin || ''))) return json(400, { error: 'PIN must be 4 digits' });
        await sql`UPDATE youth SET pin_hash = ${hashSecret(body.pin)}, failed_logins = 0, locked_until = NULL WHERE id = ${id}`;
        await audit(staff.id, 'reset_pin', id);
        return json(200, { ok: true });
      }
    }

    return json(404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    return json(500, { error: 'Something went wrong on the server' });
  }
};
