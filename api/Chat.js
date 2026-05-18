// =====================================================================
// TutorAI — API multiplexer (Vercel serverless function)
// =====================================================================
// Cambios respecto a la versión anterior:
//   - Passwords hasheadas con bcrypt (antes: TEXTO PLANO 😱)
//   - Sesiones con JWT firmado (token de 30 días)
//   - Verificación de auth por acción + rol admin
//   - Usa SUPABASE_SERVICE_KEY (no la anon key) para operaciones de backend
//   - Validación básica de inputs
//   - CORS configurable por env
// =====================================================================

import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ---- ENV VARS ----
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;
const ANTHROPIC_KEY        = process.env.ANTHROPIC_API_KEY;
const JWT_SECRET           = process.env.JWT_SECRET;
const ALLOWED_ORIGINS      = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);

// ---- ACCIONES ----
const PUBLIC_ACTIONS = new Set(['register', 'login', 'save_lead', 'view_tutorial']);
const ADMIN_ACTIONS  = new Set(['get_users', 'update_user', 'delete_user']);

// ---- SUPABASE REST HELPER ----
async function sb(method, table, body, filters) {
  let url = `${SUPABASE_URL}/rest/v1/${table}`;
  if (filters) url += `?${filters}`;
  const headers = {
    'Content-Type': 'application/json',
    'apikey': SUPABASE_SERVICE_KEY,
    'Authorization': `Bearer ${SUPABASE_SERVICE_KEY}`,
  };
  if (method === 'POST' || method === 'PATCH') headers['Prefer'] = 'return=representation';
  const res = await fetch(url, {
    method, headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Supabase ${method} ${table}: ${text}`);
  return text ? JSON.parse(text) : null;
}

// ---- JWT HELPERS ----
function signToken(user) {
  return jwt.sign(
    { sub: user.id, email: user.email, plan: user.plan, is_admin: !!user.is_admin },
    JWT_SECRET,
    { expiresIn: '30d' }
  );
}
function verifyToken(req) {
  const auth = req.headers.authorization || req.headers.Authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ---- UTILIDADES ----
const isValidEmail = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e || '');
const clean = (s, max = 200) => String(s || '').trim().slice(0, max);

function setCors(req, res) {
  const origin = req.headers.origin || '';
  const allow = ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(origin)
    ? (origin || '*')
    : ALLOWED_ORIGINS[0];
  res.setHeader('Access-Control-Allow-Origin', allow);
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

function stripPassword(user) {
  if (!user) return user;
  const { password_hash, password, ...safe } = user;
  return safe;
}

// =====================================================================
// HANDLER
// =====================================================================
export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Sanity check de env vars
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !ANTHROPIC_KEY || !JWT_SECRET) {
    return res.status(500).json({
      error: 'Server no configurado. Faltan env vars: ' +
        [
          !SUPABASE_URL && 'SUPABASE_URL',
          !SUPABASE_SERVICE_KEY && 'SUPABASE_SERVICE_KEY (o SUPABASE_ANON_KEY)',
          !ANTHROPIC_KEY && 'ANTHROPIC_API_KEY',
          !JWT_SECRET && 'JWT_SECRET',
        ].filter(Boolean).join(', ')
    });
  }

  const { action, prompt, system, data } = req.body || {};

  try {
    // -------- AUTH GUARD --------
    let session = null;
    if (action && !PUBLIC_ACTIONS.has(action)) {
      session = verifyToken(req);
      if (!session) return res.status(401).json({ error: 'No autorizado (token faltante o inválido)' });
      if (ADMIN_ACTIONS.has(action) && !session.is_admin) {
        return res.status(403).json({ error: 'Solo admin' });
      }
    }

    // ============================================================
    // AUTH — register / login
    // ============================================================
    if (action === 'register') {
      if (!data || !isValidEmail(data.email) || !data.password || data.password.length < 6 || !data.name) {
        return res.status(400).json({ error: 'Datos inválidos. Requeridos: email válido, password ≥ 6 chars, name.' });
      }
      const email = clean(data.email).toLowerCase();
      const existing = await sb('GET', 'users', null, `email=eq.${encodeURIComponent(email)}&select=id`);
      if (existing && existing.length) return res.status(409).json({ error: 'Email ya registrado' });
      const password_hash = await bcrypt.hash(data.password, 10);
      const created = await sb('POST', 'users', {
        email,
        name: clean(data.name, 100),
        password_hash,
        plan: 'free',
        avatar: clean(data.name, 100).slice(0, 2).toUpperCase(),
        workspace: clean(data.workspace || '', 100),
      });
      const user = created[0];
      return res.status(200).json({ user: stripPassword(user), token: signToken(user) });
    }

    if (action === 'login') {
      if (!data || !isValidEmail(data.email) || !data.password) {
        return res.status(400).json({ error: 'Email y password requeridos' });
      }
      const email = clean(data.email).toLowerCase();
      const users = await sb('GET', 'users', null, `email=eq.${encodeURIComponent(email)}&select=*`);
      if (!users || !users.length) return res.status(401).json({ error: 'Credenciales incorrectas' });
      const user = users[0];
      const ok = await bcrypt.compare(data.password, user.password_hash || '');
      if (!ok) return res.status(401).json({ error: 'Credenciales incorrectas' });
      return res.status(200).json({ user: stripPassword(user), token: signToken(user) });
    }

    // ============================================================
    // LEADS — público (captura del modal)
    // ============================================================
    if (action === 'save_lead') {
      if (!data || !isValidEmail(data.email)) return res.status(400).json({ error: 'Email inválido' });
      await sb('POST', 'leads', {
        name: clean(data.name || '', 100),
        email: clean(data.email).toLowerCase(),
        company: clean(data.company || '', 100),
        source: clean(data.source || 'modal', 50),
      });
      return res.status(200).json({ ok: true });
    }

    // ============================================================
    // USERS — solo admin
    // ============================================================
    if (action === 'get_users') {
      const users = await sb('GET', 'users', null,
        'select=id,email,name,plan,avatar,workspace,is_admin,tutorials_this_month,created_at&order=created_at.desc');
      return res.status(200).json({ users: users || [] });
    }
    if (action === 'update_user') {
      if (!data || !data.id) return res.status(400).json({ error: 'id requerido' });
      const patch = {};
      if (data.plan) patch.plan = data.plan;
      if (typeof data.is_admin === 'boolean') patch.is_admin = data.is_admin;
      if (typeof data.tutorials_this_month === 'number') patch.tutorials_this_month = data.tutorials_this_month;
      if (Object.keys(patch).length === 0) return res.status(400).json({ error: 'Nada para actualizar' });
      await sb('PATCH', 'users', patch, `id=eq.${data.id}`);
      return res.status(200).json({ ok: true });
    }
    if (action === 'delete_user') {
      if (!data || !data.id) return res.status(400).json({ error: 'id requerido' });
      await sb('DELETE', 'users', null, `id=eq.${data.id}`);
      return res.status(200).json({ ok: true });
    }

    // ============================================================
    // TUTORIALS — del usuario logueado (admin ve todos)
    // ============================================================
    if (action === 'get_tutorials') {
      const filter = session.is_admin
        ? 'select=*&order=created_at.desc'
        : `user_id=eq.${session.sub}&select=*&order=created_at.desc`;
      const tutorials = await sb('GET', 'tutorials', null, filter);
      return res.status(200).json({ tutorials: tutorials || [] });
    }
    if (action === 'create_tutorial') {
      if (!data || !data.title || !data.steps) {
        return res.status(400).json({ error: 'title y steps requeridos' });
      }
      const payload = {
        user_id: session.sub,
        title: clean(data.title, 200),
        source_type: data.source_type || 'text',
        language: data.language || 'es',
        format: data.format || 'text',
        steps: data.steps,
        audio_url: data.audio_url || null,
        video_url: data.video_url || null,
      };
      const tut = await sb('POST', 'tutorials', payload);
      // Incrementar contador del usuario (sin transaccionalidad estricta, suficiente para v1)
      const userRows = await sb('GET', 'users', null,
        `id=eq.${session.sub}&select=tutorials_this_month`);
      const current = (userRows && userRows[0] && userRows[0].tutorials_this_month) || 0;
      await sb('PATCH', 'users', { tutorials_this_month: current + 1 }, `id=eq.${session.sub}`);
      return res.status(200).json({ tutorial: tut[0] });
    }
    if (action === 'delete_tutorial') {
      if (!data || !data.id) return res.status(400).json({ error: 'id requerido' });
      const filter = session.is_admin
        ? `id=eq.${data.id}`
        : `id=eq.${data.id}&user_id=eq.${session.sub}`;
      await sb('DELETE', 'tutorials', null, filter);
      return res.status(200).json({ ok: true });
    }

    // ============================================================
    // VIEW TUTORIAL — público (por share_link)
    // ============================================================
    if (action === 'view_tutorial') {
      if (!data || !data.share_link) return res.status(400).json({ error: 'share_link requerido' });
      const found = await sb('GET', 'tutorials', null,
        `share_link=eq.${encodeURIComponent(data.share_link)}` +
        `&select=id,title,steps,language,format,audio_url,video_url,views`);
      if (!found || !found.length) return res.status(404).json({ error: 'Tutorial no encontrado' });
      // Incrementar views (fire-and-forget)
      sb('PATCH', 'tutorials',
        { views: (found[0].views || 0) + 1 },
        `id=eq.${found[0].id}`).catch(() => {});
      return res.status(200).json({ tutorial: found[0] });
    }

    // ============================================================
    // COMPLETIONS — quién consumió el tutorial
    // ============================================================
    if (action === 'save_completion') {
      if (!data || !data.tutorial_id) return res.status(400).json({ error: 'tutorial_id requerido' });
      const comp = await sb('POST', 'completions', {
        tutorial_id: data.tutorial_id,
        viewer_email: clean(data.viewer_email || '', 200),
        viewer_name: clean(data.viewer_name || '', 100),
        completed: !!data.completed,
        watched_seconds: parseInt(data.watched_seconds || 0, 10),
      });
      return res.status(200).json({ completion: comp[0] });
    }
    if (action === 'get_completions') {
      if (!data || !data.tutorial_id) return res.status(400).json({ error: 'tutorial_id requerido' });
      // Verificar dueño del tutorial
      const t = await sb('GET', 'tutorials', null,
        `id=eq.${data.tutorial_id}&select=user_id`);
      if (!t || !t.length) return res.status(404).json({ error: 'Tutorial no encontrado' });
      if (!session.is_admin && t[0].user_id !== session.sub) {
        return res.status(403).json({ error: 'Acceso denegado' });
      }
      const comps = await sb('GET', 'completions', null,
        `tutorial_id=eq.${data.tutorial_id}&select=*&order=created_at.desc`);
      return res.status(200).json({ completions: comps || [] });
    }

    // ============================================================
    // CLAUDE — prompt directo (requiere login)
    // ============================================================
    if (prompt) {
      const tok = verifyToken(req);
      if (!tok) return res.status(401).json({ error: 'No autorizado' });

      const body = {
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        messages: [{ role: 'user', content: prompt }],
      };
      if (system) body.system = system;

      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': ANTHROPIC_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify(body),
      });
      const d = await r.json();
      if (!r.ok) {
        return res.status(500).json({ error: d?.error?.message || 'Claude error' });
      }
      const text = d.content?.map(b => b.text || '').join('\n') || '';
      return res.status(200).json({ text });
    }

    return res.status(400).json({ error: 'action o prompt requeridos' });
  } catch (e) {
    console.error('[/api/chat] error:', e);
    return res.status(500).json({ error: e.message });
  }
}
