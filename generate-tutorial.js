// =====================================================================
// TutorAI — Generador de tutoriales con IA (Vercel serverless function)
// =====================================================================
// Recibe una foto / PDF / link / texto, se lo manda a Claude (con visión
// cuando hay imagen o PDF), y devuelve un tutorial estructurado en pasos
// + un guion para narrar. Guarda el tutorial en Supabase y controla el
// límite mensual segun el plan del usuario.
//
// No necesita ninguna env var nueva: usa las mismas que /api/chat.
//   SUPABASE_URL · SUPABASE_SERVICE_KEY · ANTHROPIC_API_KEY · JWT_SECRET
// =====================================================================

import jwt from 'jsonwebtoken';

// Vercel: dar hasta 60s a la función (generar con IA puede tardar 15-30s).
// Sin esto, el plan gratuito corta a los 10s y la generación falla.
export const maxDuration = 60;

// ---- ENV VARS ----
const SUPABASE_URL         = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY || process.env.SUPABASE_ANON_KEY;
const ANTHROPIC_KEY        = process.env.ANTHROPIC_API_KEY;
const JWT_SECRET           = process.env.JWT_SECRET;
const ALLOWED_ORIGINS      = (process.env.ALLOWED_ORIGINS || '*')
  .split(',').map(s => s.trim()).filter(Boolean);

// ---- LIMITES POR PLAN ----
const PLAN_LIMITS  = { free: 5, starter: 20, pro: 100000, empresa: 100000 };
const PLAN_FORMATS = {
  free:    ['text'],
  starter: ['text', 'voice'],
  pro:     ['text', 'voice', 'video'],
  empresa: ['text', 'voice', 'video'],
};

const LANG_NAMES = {
  es: 'español', en: 'inglés', pt: 'portugués', fr: 'francés',
  de: 'alemán', it: 'italiano', zh: 'chino', ja: 'japonés',
};
const SOURCE_TYPES = ['photo', 'pdf', 'voice', 'link', 'text'];

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

// ---- JWT ----
function verifyToken(req) {
  const auth = req.headers.authorization || req.headers.Authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ---- CORS ----
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

// =====================================================================
// HANDLER
// =====================================================================
export default async function handler(req, res) {
  setCors(req, res);
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY || !ANTHROPIC_KEY || !JWT_SECRET) {
    return res.status(500).json({
      error: 'Server no configurado. Faltan env vars: ' +
        [
          !SUPABASE_URL && 'SUPABASE_URL',
          !SUPABASE_SERVICE_KEY && 'SUPABASE_SERVICE_KEY',
          !ANTHROPIC_KEY && 'ANTHROPIC_API_KEY',
          !JWT_SECRET && 'JWT_SECRET',
        ].filter(Boolean).join(', '),
    });
  }

  // -------- AUTH --------
  const session = verifyToken(req);
  if (!session) return res.status(401).json({ error: 'No autorizado. Iniciá sesión para generar tutoriales.' });

  try {
    const {
      source_type = 'text',
      content = '',
      url = '',
      image = null,
      pdf = null,
      language = 'es',
      format = 'text',
    } = req.body || {};

    const st = SOURCE_TYPES.includes(source_type) ? source_type : 'text';
    const lang = LANG_NAMES[language] ? language : 'es';
    const fmt = ['text', 'voice', 'video'].includes(format) ? format : 'text';

    // -------- USUARIO + LIMITES --------
    const users = await sb('GET', 'users', null, `id=eq.${session.sub}&select=*`);
    if (!users || !users.length) return res.status(404).json({ error: 'Usuario no encontrado' });
    let user = users[0];

    // Reset del contador si arrancó un mes nuevo
    const monthStart = new Date();
    monthStart.setUTCDate(1);
    monthStart.setUTCHours(0, 0, 0, 0);
    if (user.month_reset_at && new Date(user.month_reset_at) < monthStart) {
      await sb('PATCH', 'users',
        { tutorials_this_month: 0, month_reset_at: new Date().toISOString() },
        `id=eq.${user.id}`);
      user.tutorials_this_month = 0;
    }

    const plan  = user.plan || 'free';
    const limit = PLAN_LIMITS[plan] ?? 5;
    const used  = user.tutorials_this_month || 0;
    if (used >= limit) {
      return res.status(403).json({
        error: `Llegaste al límite de tu plan ${plan.toUpperCase()} (${limit} tutoriales este mes). ` +
               `Mejorá tu plan para seguir generando.`,
      });
    }
    const allowedFormats = PLAN_FORMATS[plan] || ['text'];
    if (!allowedFormats.includes(fmt)) {
      const nice = { text: 'Texto', voice: 'Voz', video: 'Video' };
      return res.status(403).json({
        error: `El formato "${nice[fmt] || fmt}" no está disponible en el plan ${plan.toUpperCase()}. ` +
               `Tu plan permite: ${allowedFormats.map(f => nice[f]).join(', ')}.`,
      });
    }

    // -------- ARMAR EL CONTENIDO PARA CLAUDE --------
    const langName = LANG_NAMES[lang];
    const userContent = [];
    let inputDesc = '';

    if (image) {
      const m = /^data:(image\/[a-zA-Z0-9.+-]+);base64,(.+)$/.exec(String(image));
      if (!m) return res.status(400).json({ error: 'Imagen inválida.' });
      userContent.push({ type: 'image', source: { type: 'base64', media_type: m[1], data: m[2] } });
      inputDesc = 'El usuario adjuntó una foto / captura de pantalla. Analizala con detalle: identificá qué programa o pantalla es y qué se ve.';
    } else if (pdf) {
      const m = /^data:application\/pdf;base64,(.+)$/.exec(String(pdf));
      if (!m) return res.status(400).json({ error: 'PDF inválido.' });
      userContent.push({ type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: m[1] } });
      inputDesc = 'El usuario adjuntó un documento PDF. Leelo y extraé el procedimiento o instrucciones que contiene.';
    } else if (url) {
      let pageText = '';
      try {
        const r = await fetch(String(url), {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; TutorAI/1.0)' },
        });
        const html = await r.text();
        pageText = html
          .replace(/<script[\s\S]*?<\/script>/gi, ' ')
          .replace(/<style[\s\S]*?<\/style>/gi, ' ')
          .replace(/<[^>]+>/g, ' ')
          .replace(/&nbsp;/gi, ' ')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 6000);
      } catch (e) {
        pageText = '';
      }
      if (!pageText) return res.status(400).json({ error: 'No pude leer el contenido de ese link. Probá con otro o pegá el texto.' });
      inputDesc = `Contenido extraído de la página ${url}:\n\n${pageText}`;
    } else {
      const txt = String(content || '').trim();
      if (!txt) return res.status(400).json({ error: 'Falta el contenido: subí una foto/PDF, pegá un link o escribí el tema.' });
      inputDesc = `El usuario quiere un tutorial sobre lo siguiente:\n\n${txt.slice(0, 8000)}`;
    }

    userContent.push({
      type: 'text',
      text: `${inputDesc}\n\nGenerá un tutorial paso a paso, claro y práctico, EN ${langName.toUpperCase()}. ` +
            `Pensado para una persona sin experiencia previa.`,
    });

    const system = `Sos un experto en crear tutoriales claros para principiantes.
A partir del material que te pasa el usuario, generás un tutorial paso a paso.

Respondé ÚNICAMENTE con un objeto JSON válido. SIN markdown, SIN bloques de codigo, SIN texto antes ni después.
El JSON debe tener EXACTAMENTE esta forma:
{
  "title": "título corto y claro del tutorial",
  "program": "nombre del programa o herramienta detectado, o cadena vacía si no aplica",
  "summary": "1 o 2 frases que resumen qué se va a aprender",
  "steps": [
    { "n": 1, "title": "título corto del paso", "instruction": "explicación clara, concreta y accionable del paso", "tip": "consejo útil opcional, o cadena vacía" }
  ],
  "narration": "guion corrido y natural para narrar el tutorial en voz alta, mencionando cada paso de forma fluida"
}

Reglas obligatorias:
- Entre 4 y 9 pasos.
- TODO el texto (title, program, summary, steps, narration) debe estar en ${langName}.
- Las instrucciones deben ser accionables (qué hacer, dónde hacer clic, qué escribir).
- El JSON tiene que ser válido y parseable. No uses comillas sin escapar dentro de los textos.`;

    // -------- LLAMADA A CLAUDE --------
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_KEY,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 4096,
        system,
        messages: [{ role: 'user', content: userContent }],
      }),
    });
    const d = await r.json();
    if (!r.ok) {
      return res.status(502).json({ error: d?.error?.message || 'Error al generar con Claude.' });
    }

    let raw = (d.content || []).map(b => b.text || '').join('\n').trim();
    const first = raw.indexOf('{');
    const last  = raw.lastIndexOf('}');
    if (first < 0 || last < 0) {
      return res.status(502).json({ error: 'La IA no devolvió un tutorial con el formato esperado. Probá de nuevo.' });
    }
    let parsed;
    try {
      parsed = JSON.parse(raw.slice(first, last + 1));
    } catch (e) {
      return res.status(502).json({ error: 'No pude interpretar la respuesta de la IA. Probá de nuevo.' });
    }

    const steps = Array.isArray(parsed.steps)
      ? parsed.steps.map((s, i) => ({
          n: Number(s.n) || i + 1,
          title: String(s.title || `Paso ${i + 1}`).slice(0, 200),
          instruction: String(s.instruction || '').slice(0, 1200),
          tip: String(s.tip || '').slice(0, 400),
        })).filter(s => s.instruction)
      : [];
    if (!steps.length) {
      return res.status(502).json({ error: 'La IA no generó pasos. Probá con otro contenido.' });
    }

    const title = String(parsed.title || 'Tutorial sin título').slice(0, 200);
    const stepsPayload = {
      list: steps,
      narration: String(parsed.narration || '').slice(0, 9000),
      summary: String(parsed.summary || '').slice(0, 600),
      program: String(parsed.program || '').slice(0, 120),
    };

    // -------- GUARDAR EN SUPABASE --------
    const created = await sb('POST', 'tutorials', {
      user_id: user.id,
      title,
      source_type: st,
      language: lang,
      format: fmt,
      steps: stepsPayload,
    });
    const tutorial = created[0];

    // Incrementar el contador mensual
    await sb('PATCH', 'users',
      { tutorials_this_month: used + 1 },
      `id=eq.${user.id}`);

    return res.status(200).json({
      tutorial,
      usage: { used: used + 1, limit },
    });
  } catch (e) {
    console.error('[/api/generate-tutorial] error:', e);
    return res.status(500).json({ error: e.message });
  }
}
