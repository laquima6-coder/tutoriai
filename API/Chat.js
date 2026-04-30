const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY;
const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;

async function sb(method, table, body, filters) {
  let url = `${SUPABASE_URL}/rest/v1/${table}`;
  if (filters) url += `?${filters}`;
  const res = await fetch(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Prefer': method === 'POST' ? 'return=representation' : '',
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(text);
  return text ? JSON.parse(text) : null;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { action, prompt, system, data } = req.body || {};

  try {
    // REGISTER
    if (action === 'register') {
      const existing = await sb('GET','users',null,`email=eq.${encodeURIComponent(data.email)}&select=id`);
      if (existing && existing.length > 0) return res.status(400).json({ error: 'Email ya registrado' });
      const user = await sb('POST','users',{ email:data.email, name:data.name, password:data.password, plan:'free', avatar:data.name.slice(0,2).toUpperCase(), workspace:'' });
      return res.status(200).json({ user: user[0] });
    }

    // LOGIN
    if (action === 'login') {
      const users = await sb('GET','users',null,`email=eq.${encodeURIComponent(data.email)}&select=*`);
      if (!users || users.length === 0) return res.status(401).json({ error: 'Credenciales incorrectas' });
      if (users[0].password !== data.password) return res.status(401).json({ error: 'Credenciales incorrectas' });
      return res.status(200).json({ user: users[0] });
    }

    // GET USERS
    if (action === 'get_users') {
      const users = await sb('GET','users',null,'select=*&order=created_at.desc');
      return res.status(200).json({ users: users || [] });
    }

    // UPDATE USER PLAN
    if (action === 'update_user') {
      await sb('PATCH','users',{ plan: data.plan },`id=eq.${data.id}`);
      return res.status(200).json({ ok: true });
    }

    // DELETE USER
    if (action === 'delete_user') {
      await sb('DELETE','users',null,`id=eq.${data.id}`);
      return res.status(200).json({ ok: true });
    }

    // GET TUTORIALS
    if (action === 'get_tutorials') {
      const tutorials = await sb('GET','tutorials',null,'select=*&order=created_at.desc');
      return res.status(200).json({ tutorials: tutorials || [] });
    }

    // CREATE TUTORIAL
    if (action === 'create_tutorial') {
      const tut = await sb('POST','tutorials', data);
      return res.status(200).json({ tutorial: tut[0] });
    }

    // DELETE TUTORIAL
    if (action === 'delete_tutorial') {
      await sb('DELETE','tutorials',null,`id=eq.${data.id}`);
      return res.status(200).json({ ok: true });
    }

    // GET COMPLETIONS
    if (action === 'get_completions') {
      const completions = await sb('GET','completions',null,'select=*&order=created_at.desc');
      return res.status(200).json({ completions: completions || [] });
    }

    // SAVE COMPLETION
    if (action === 'save_completion') {
      const comp = await sb('POST','completions', data);
      return res.status(200).json({ completion: comp[0] });
    }

    // CLAUDE AI
    if (prompt) {
      const body = { model:'claude-sonnet-4-20250514', max_tokens:1500, messages:[{role:'user',content:prompt}] };
      if (system) body.system = system;
      const r = await fetch('https://api.anthropic.com/v1/messages', {
        method: 'POST',
        headers: { 'Content-Type':'application/json', 'x-api-key':ANTHROPIC_KEY, 'anthropic-version':'2023-06-01' },
        body: JSON.stringify(body)
      });
      const d = await r.json();
      const text = d.content?.map(b => b.text||'').join('\n') || '';
      return res.status(200).json({ text });
    }

    return res.status(400).json({ error: 'action or prompt required' });

  } catch(e) {
    return res.status(500).json({ error: e.message });
  }
}
