const { neon } = require('@neondatabase/serverless');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const sql = neon(process.env.DATABASE_URL);
const SESSION_HOURS = 12;

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
  const [kind, salt, hash] = String(stored).split('$');
  if (kind !== 'scrypt') return false;
  const test = crypto.scryptSync(String(secret), salt, 64);
  const want = Buffer.from(hash, 'hex');
  return want.length === test.length && crypto.timingSafeEqual(want, test);
}

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
  const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}

async function currentStaff(event) {
  const auth = event.headers.authorization || event.headers.Authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  const payload = verify(token);
  if (!payload) return null;
  const rows = await sql`SELECT id, email, name, role FROM staff WHERE id = ${payload.sid}`;
  return rows[0] || null;
}

async function audit(staffId, action, target) {
  await sql`INSERT INTO audit_log (staff_id, action, target) VALUES (${staffId}, ${action}, ${target})`;
}

function parseBody(event) {
  try { return event.body ? JSON.parse(event.body) : {}; } catch { return null; }
}

exports.handler = async (event) => {
  const route = (event.path || '').replace(/^.*\/api/, '').replace(/\/+$/, '') || '/';
  const method = event.httpMethod;

  // Health check: reports database problems in plain terms (no secrets).
  if (route === '/health' && method === 'GET') {
    try {
      await sql`SELECT 1 AS ok`;
      await ensureSchema();
      const staffCount = (await sql`SELECT count(*)::int AS n FROM staff`)[0].n;
      const sc = process.env.SETUP_CODE || '';
      return json(200, {
        ok: true,
        database: 'connected',
        staffAccounts: staffCount,
        setupCodeSet: sc.length > 0,
        setupCodeLength: sc.length,
        setupCodeHasWhitespace: /\s/.test(sc),
        sessionSecretSet: Boolean(process.env.STAFF_SESSION_SECRET)
      });
    } catch (err) {
      return json(500, { ok: false, errorName: err.name, code: err.code || null, message: String(err.message || '').slice(0, 300) });
    }
  }

  try {
    await ensureSchema();
    const body = parseBody(event);
    if (body === null) return json(400, { error: 'Invalid JSON' });

    // First-time setup: only while there are no staff accounts, and only with SETUP_CODE.
    if (route === '/setup' && method === 'POST') {
      const count = (await sql`SELECT count(*)::int AS n FROM staff`)[0].n;
      if (count > 0) return json(404, { error: 'Not found' });
      if (!process.env.SETUP_CODE) return json(403, { error: 'SETUP_CODE is not set on the server. Add it in Netlify and redeploy.' });
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
      const token = sign({ sid: s.id, exp: Date.now() + SESSION_HOURS * 3600 * 1000 });
      await audit(s.id, 'login', s.email);
      return json(200, { token, staff: { id: s.id, email: s.email, name: s.name, role: s.role } });
    }

    const staff = await currentStaff(event);
    if (!staff) return json(401, { error: 'Sign in first' });

    if (route === '/me' && method === 'GET') return json(200, { staff });

    if (route === '/youth' && method === 'GET') {
      const rows = await sql`
        SELECT y.id, y.first_name, y.last_name, y.site, y.consent_on_file, y.consent_date, y.created_at,
          (SELECT count(*)::int FROM lesson_progress p WHERE p.youth_id = y.id) AS lessons_done,
          (SELECT max(v.visited_at) FROM mentor_visits v WHERE v.youth_id = y.id) AS last_visit
        FROM youth y ORDER BY y.last_name, y.first_name`;
      return json(200, { youth: rows });
    }

    if (route === '/youth' && method === 'POST') {
      if (!body.firstName || !body.lastName || !['jdc', 'stars'].includes(body.site)) return json(400, { error: 'First name, last name, and site (jdc or stars) are required' });
      if (!body.consentOnFile || !body.guardianName || !body.guardianRelation) return json(400, { error: 'Guardian permission must be on file before an account is created' });
      if (!/^\d{4}$/.test(String(body.pin || ''))) return json(400, { error: 'PIN must be 4 digits' });
      const rows = await sql`
        INSERT INTO youth (first_name, last_name, site, pin_hash, consent_on_file, consent_date, guardian_name, guardian_relation, guardian_phone, interests, intake)
        VALUES (${body.firstName}, ${body.lastName}, ${body.site}, ${hashSecret(body.pin)}, true, ${body.consentDate || new Date().toISOString().slice(0, 10)},
                ${body.guardianName}, ${body.guardianRelation}, ${body.guardianPhone || null}, ${JSON.stringify(body.interests || [])}::jsonb, ${JSON.stringify(body.intake || {})}::jsonb)
        RETURNING id, first_name, last_name, site, consent_on_file, consent_date`;
      await audit(staff.id, 'create_youth', rows[0].id);
      return json(201, { youth: rows[0] });
    }

    const m = route.match(/^\/youth\/([0-9a-f-]{36})(\/[a-z-]+)?$/);
    if (m) {
      const id = m[1];
      const action = m[2] || '';
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
    }

    return json(404, { error: 'Not found' });
  } catch (err) {
    console.error(err);
    return json(500, { error: 'Something went wrong on the server' });
  }
};
