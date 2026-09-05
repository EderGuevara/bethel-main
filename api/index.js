const express   = require('express');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const crypto    = require('crypto');
const bcrypt    = require('bcryptjs');
const { promisify } = require('util');
const { Redis } = require('@upstash/redis');
const { Resend } = require('resend');

const scrypt = promisify(crypto.scrypt);

const app = express();
app.use(cors());
app.use(express.json({ limit: '20mb' }));

const kv = new Redis({
  url:   process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

let blobPut, blobDel;
try { const b = require('@vercel/blob'); blobPut = b.put; blobDel = b.del; } catch {}

const JWT_SECRET  = process.env.JWT_SECRET     || 'bethel-main-secret';
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL   || 'office@bethelfinancialgroup.com').toLowerCase();
const ADMIN_PW    = process.env.ADMIN_PLAIN_PW || '';

// Key prefix keeps bethel-main data separate from bethel-exam-prep in the shared KV store
const K = (key) => 'main:' + key;

const nowISO      = () => new Date().toISOString();
const makeToken   = p  => jwt.sign(p, JWT_SECRET, { expiresIn: '30d' });
const verifyToken = t  => { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };

function requireAdmin(req, res, next) {
  const d = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!d || !d.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  req.user = d;
  next();
}

// requireAgent re-checks the agent's current `licensed` flag against Redis on every
// request (rather than trusting the JWT claim) so revoking a license takes effect
// immediately, not just after the agent's existing token expires. Handles both native
// bethel-main agent accounts (d.agentId) and life-course accounts (d.examEmail).
async function requireAgent(req, res, next) {
  const d = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!d) return res.status(403).json({ error: 'Forbidden' });
  if (d.isAdmin) { req.user = d; return next(); }
  try {
    if (d.agentId) {
      const agents = (await kv.get(K('agents'))) || [];
      const agent = agents.find(a => a.id === d.agentId);
      if (!agent || !agent.licensed) return res.status(403).json({ error: 'Forbidden' });
      req.user = d;
      return next();
    }
    if (d.examEmail) {
      const examUser = await kv.get('user:' + d.examEmail);
      if (!examUser || !examUser.licensed) return res.status(403).json({ error: 'Forbidden' });
      req.user = d;
      return next();
    }
    res.status(403).json({ error: 'Forbidden' });
  } catch { res.status(500).json({ error: 'Server error.' }); }
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = (await scrypt(password, salt, 64)).toString('hex');
  return { salt, hash };
}
async function verifyPassword(password, salt, hash) {
  if (!salt || !hash) return false;
  const check = (await scrypt(password, salt, 64)).toString('hex');
  try { return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(hash, 'hex')); }
  catch { return false; }
}

// ── AUTH ────────────────────────────────────────────────────────────────────

app.post('/api/login', async (req, res) => {
  const { email = '', password = '' } = req.body || {};
  const emailLower = email.toLowerCase();
  if (emailLower === ADMIN_EMAIL && password === ADMIN_PW && password)
    return res.json({ token: makeToken({ email: ADMIN_EMAIL, isAdmin: true }), isAdmin: true, name: 'Admin' });
  try {
    // 1) Native bethel-main agent account (added directly via admin, own password)
    const agents = (await kv.get(K('agents'))) || [];
    const agent = agents.find(a => a.email === emailLower);
    if (agent && agent.passwordHash) {
      const ok = await verifyPassword(password, agent.passwordSalt, agent.passwordHash);
      if (ok) {
        const token = makeToken({ agentId: agent.id, email: agent.email, licensed: !!agent.licensed });
        return res.json({ token, name: agent.name, licensed: !!agent.licensed });
      }
    }

    // 2) Fall back to the life-course account — same email/password used there.
    // Portal access follows that app's "licensed" toggle, checked live (see requireAgent).
    const examUser = await kv.get('user:' + emailLower);
    if (examUser && examUser.hash) {
      const ok = await bcrypt.compare(password, examUser.hash);
      if (ok) {
        if (!examUser.licensed) return res.status(403).json({ error: 'Portal access is restricted to licensed agents. Contact your admin.' });
        const token = makeToken({ examEmail: emailLower, licensed: true });
        return res.json({ token, name: examUser.name, licensed: true });
      }
    }

    res.status(401).json({ error: 'Invalid credentials.' });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/me', async (req, res) => {
  const d = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!d) return res.status(403).json({ error: 'Unauthorized' });
  if (d.isAdmin) return res.json({ email: d.email, isAdmin: true, name: 'Admin' });
  try {
    if (d.agentId) {
      const agents = (await kv.get(K('agents'))) || [];
      const agent = agents.find(a => a.id === d.agentId);
      if (!agent) return res.status(403).json({ error: 'Unauthorized' });
      return res.json({ email: agent.email, isAdmin: false, licensed: !!agent.licensed, name: agent.name });
    }
    if (d.examEmail) {
      const examUser = await kv.get('user:' + d.examEmail);
      if (!examUser) return res.status(403).json({ error: 'Unauthorized' });
      return res.json({ email: d.examEmail, isAdmin: false, licensed: !!examUser.licensed, name: examUser.name });
    }
    res.json({ email: d.email, isAdmin: !!d.isAdmin });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// ── AGENTS ──────────────────────────────────────────────────────────────────
// Agent accounts gate access to the Agent Portal. Only accounts with
// licensed:true can sign in there; admin toggles this per agent.

app.get('/api/admin/agents', requireAdmin, async (req, res) => {
  try {
    const agents = (await kv.get(K('agents'))) || [];
    const native = agents.map(a => ({ source: 'native', id: a.id, name: a.name, email: a.email, licensed: !!a.licensed, hasPassword: !!a.passwordHash, createdAt: a.createdAt }));
    const nativeEmails = new Set(native.map(a => a.email));

    // Merge in life-course accounts currently marked licensed there — same shared
    // KV store, keyed by users:index (list of emails) + user:<email> records.
    let examAgents = [];
    try {
      const index = (await kv.get('users:index')) || [];
      if (index.length) {
        const users = await kv.mget(...index.map(e => 'user:' + e));
        examAgents = users
          .filter(u => u && u.licensed && !nativeEmails.has(u.email))
          .map(u => ({ source: 'exam-prep', email: u.email, name: u.name, licensed: true, hasPassword: true, createdAt: u.createdAt || null }));
      }
    } catch {}

    res.json([...native, ...examAgents]);
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// POST /api/admin/exam-agents/:email/revoke — remove portal access for a licensed
// life-course account. Only flips their `licensed` flag; their course account and
// progress are untouched.
app.post('/api/admin/exam-agents/:email/revoke', requireAdmin, async (req, res) => {
  try {
    const email = decodeURIComponent(req.params.email).toLowerCase();
    const key = 'user:' + email;
    const examUser = await kv.get(key);
    if (!examUser) return res.status(404).json({ error: 'Not found.' });
    examUser.licensed = false;
    await kv.set(key, examUser);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// ── LANDING PAGE CONTENT OVERRIDES ───────────────────────────────────────────
// Lets an admin edit live landing-page text directly from the public page
// (Edit Mode) with no code deploy. Overrides are merged over the hardcoded
// PT translation objects in index.html at load time, keyed by data-t id.

app.get('/api/landing/overrides', async (req, res) => {
  try { res.json((await kv.get(K('landing:overrides'))) || {}); }
  catch { res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/admin/landing-overrides', requireAdmin, async (req, res) => {
  try {
    const { lang, overrides, hiddenBlocks } = req.body || {};
    if (lang !== 'en' && lang !== 'es') return res.status(400).json({ error: 'Invalid language.' });
    if (!overrides || typeof overrides !== 'object') return res.status(400).json({ error: 'Invalid overrides.' });
    const current = (await kv.get(K('landing:overrides'))) || {};
    current[lang] = Object.assign({}, current[lang] || {}, overrides);
    if (Array.isArray(hiddenBlocks)) current.hiddenBlocks = hiddenBlocks;
    await kv.set(K('landing:overrides'), current);
    res.json({ ok: true, overrides: current });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// Landing-page images: stored directly in Redis as base64 (same pattern as
// announcement images) and served via GET /api/landing/image/:key. Avoids
// Vercel Blob entirely — this project's Blob store only allows private
// access, which doesn't work for a plain public <img src>.
const LANDING_IMAGE_DEFAULTS = { logo: '/assets/Logo.JPG', founders: '/assets/founders.jpg' };

app.post('/api/admin/landing-image', requireAdmin, async (req, res) => {
  try {
    const { key, fileData } = req.body || {};
    if (!key || !fileData) return res.status(400).json({ error: 'Missing key or image data.' });
    await kv.set(K('landing:img:' + key), fileData);
    res.json({ ok: true, url: '/api/landing/image/' + key + '?v=' + Date.now() });
  } catch (e) { res.status(500).json({ error: 'Upload failed: ' + e.message }); }
});

app.get('/api/landing/image/:key', async (req, res) => {
  try {
    const key = req.params.key;
    const b64 = await kv.get(K('landing:img:' + key));
    if (!b64) {
      const fallback = LANDING_IMAGE_DEFAULTS[key];
      if (fallback) return res.redirect(302, fallback);
      return res.status(404).send('Not found');
    }
    const match = String(b64).match(/^data:([^;]+);base64,(.+)$/);
    let contentType = 'image/jpeg';
    let data = b64;
    if (match) { contentType = match[1]; data = match[2]; }
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=300');
    res.send(Buffer.from(String(data), 'base64'));
  } catch (e) { res.status(500).send('Server error'); }
});

function buildSetupUrl(agentId) {
  const setupToken = jwt.sign({ agentId, purpose: 'agent-setup' }, JWT_SECRET, { expiresIn: '7d' });
  return 'https://www.bethelfinancialgroup.com/portal?setup=' + setupToken;
}

async function emailAgentSetup(agent, setupUrl) {
  const key = process.env.RESEND_API_KEY;
  if (!key) return;
  const resend = new Resend(key);
  await resend.emails.send({
    from: process.env.RESEND_FROM_EMAIL || 'noreply@bethelfinancialgroup.com',
    to: agent.email,
    subject: 'Set up your Bethel Financial Group Agent Portal access',
    html: `<p>Hi ${agent.name},</p><p>You've been added as a licensed agent. Set your password to access the Agent Portal:</p><p><a href="${setupUrl}">${setupUrl}</a></p><p>This link expires in 7 days.</p>`,
  }).catch(() => {});
}

app.post('/api/admin/agents', requireAdmin, async (req, res) => {
  try {
    const { name, email, licensed } = req.body || {};
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required.' });
    const emailLower = String(email).toLowerCase().trim();
    const agents = (await kv.get(K('agents'))) || [];
    if (agents.some(a => a.email === emailLower)) return res.status(400).json({ error: 'An agent with this email already exists.' });
    const agent = { id: Date.now(), name: name.trim(), email: emailLower, passwordHash: null, passwordSalt: null, licensed: !!licensed, createdAt: nowISO() };
    agents.push(agent);
    await kv.set(K('agents'), agents);
    const setupUrl = buildSetupUrl(agent.id);
    emailAgentSetup(agent, setupUrl);
    res.json({ ok: true, agent: { id: agent.id, name: agent.name, email: agent.email, licensed: agent.licensed }, setupUrl });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

app.put('/api/admin/agents/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { name, licensed, resendSetup } = req.body || {};
    const agents = (await kv.get(K('agents'))) || [];
    const idx = agents.findIndex(a => a.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Not found.' });
    if (name !== undefined)      agents[idx].name     = name.trim();
    if (licensed !== undefined)  agents[idx].licensed = !!licensed;
    let setupUrl = null;
    if (resendSetup) {
      setupUrl = buildSetupUrl(agents[idx].id);
      emailAgentSetup(agents[idx], setupUrl);
    }
    await kv.set(K('agents'), agents);
    res.json({ ok: true, agent: { id: agents[idx].id, name: agents[idx].name, email: agents[idx].email, licensed: agents[idx].licensed }, setupUrl });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

app.delete('/api/admin/agents/:id', requireAdmin, async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const agents = (await kv.get(K('agents'))) || [];
    await kv.set(K('agents'), agents.filter(a => a.id !== id));
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// POST /api/agent/setup-info — tells the password screen which account a setup
// link belongs to, so the agent can see the email they're creating credentials
// for. Deliberately returns no session: the link alone must not grant access.
app.post('/api/agent/setup-info', async (req, res) => {
  try {
    const { token: setupToken } = req.body || {};
    if (!setupToken) return res.status(400).json({ error: 'Missing token.' });
    const d = verifyToken(setupToken);
    if (!d || d.purpose !== 'agent-setup') return res.status(400).json({ error: 'This link is invalid or has expired.' });
    const agents = (await kv.get(K('agents'))) || [];
    const agent = agents.find(a => a.id === d.agentId);
    if (!agent) return res.status(404).json({ error: 'Agent not found.' });
    if (!agent.licensed) return res.status(403).json({ error: 'Portal access is restricted to licensed agents. Contact your admin.' });
    res.json({ ok: true, name: agent.name, email: agent.email, hasPassword: !!agent.passwordHash });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// POST /api/agent/set-password — public, but requires a valid one-time setup token
app.post('/api/agent/set-password', async (req, res) => {
  try {
    const { token: setupToken, password } = req.body || {};
    if (!setupToken || !password) return res.status(400).json({ error: 'Missing token or password.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    const d = verifyToken(setupToken);
    if (!d || d.purpose !== 'agent-setup') return res.status(400).json({ error: 'This link is invalid or has expired.' });
    const agents = (await kv.get(K('agents'))) || [];
    const idx = agents.findIndex(a => a.id === d.agentId);
    if (idx === -1) return res.status(404).json({ error: 'Agent not found.' });
    const { salt, hash } = await hashPassword(password);
    agents[idx].passwordSalt = salt;
    agents[idx].passwordHash = hash;
    await kv.set(K('agents'), agents);
    const loginToken = makeToken({ agentId: agents[idx].id, email: agents[idx].email, licensed: !!agents[idx].licensed });
    res.json({ ok: true, token: loginToken, name: agents[idx].name, licensed: !!agents[idx].licensed });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// ── RESOURCES ───────────────────────────────────────────────────────────────

app.get('/api/portal/resources', requireAgent, async (req, res) => {
  try { res.json((await kv.get(K('portal:resources'))) || []); }
  catch { res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/portal/resources/upload', requireAdmin, async (req, res) => {
  try {
    const { name, description, category, fileData, filename, mimetype, size, url, logoUrl } = req.body;
    if (!name) return res.status(400).json({ error: 'Name required.' });
    let resourceUrl = url || null;
    if (fileData && filename) {
      if (!blobPut) return res.status(503).json({ error: 'File storage not configured. Use a URL instead.' });
      const buf  = Buffer.from(fileData.replace(/^data:[^;]+;base64,/, ''), 'base64');
      const safe = filename.replace(/[^a-zA-Z0-9._-]/g, '_');
      resourceUrl = (await blobPut(`portal/${Date.now()}_${safe}`, buf, { access: 'public', contentType: mimetype || 'application/octet-stream' })).url;
    }
    if (!resourceUrl) return res.status(400).json({ error: 'File or URL required.' });
    const list = (await kv.get(K('portal:resources'))) || [];
    const item = { id: Date.now(), name, description: description || '', category: category || 'Documents', url: resourceUrl, filename: filename || name, size: size || null, mimetype: mimetype || null, logoUrl: logoUrl || null, uploadedAt: nowISO() };
    list.unshift(item);
    await kv.set(K('portal:resources'), list);
    res.json({ ok: true, resource: item });
  } catch(e) { res.status(500).json({ error: 'Upload failed: ' + e.message }); }
});

app.put('/api/portal/resources/:id', requireAdmin, async (req, res) => {
  try {
    const id   = parseInt(req.params.id);
    const { name, description, category, url, logoUrl } = req.body;
    const list = (await kv.get(K('portal:resources'))) || [];
    const idx  = list.findIndex(r => r.id === id);
    if (idx === -1) return res.status(404).json({ error: 'Not found.' });
    if (name)                      list[idx].name        = name;
    if (description !== undefined) list[idx].description = description;
    if (category)                  list[idx].category    = category;
    if (url)                       list[idx].url         = url;
    list[idx].logoUrl = logoUrl || null;
    await kv.set(K('portal:resources'), list);
    res.json({ ok: true, resource: list[idx] });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

app.delete('/api/portal/resources/:id', requireAdmin, async (req, res) => {
  try {
    const id   = parseInt(req.params.id);
    const list = (await kv.get(K('portal:resources'))) || [];
    const item = list.find(r => r.id === id);
    if (!item) return res.status(404).json({ error: 'Not found.' });
    try { if (blobDel && item.url && item.url.includes('vercel-storage')) await blobDel(item.url); } catch {}
    await kv.set(K('portal:resources'), list.filter(r => r.id !== id));
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// ── ANNOUNCEMENTS ───────────────────────────────────────────────────────────

app.get('/api/portal/announcements', requireAgent, async (req, res) => {
  try { res.json((await kv.get(K('portal:announcements'))) || []); }
  catch { res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/portal/announcements', requireAdmin, async (req, res) => {
  try {
    const { title, body, pinned, imageBase64 } = req.body;
    if (!title || !body) return res.status(400).json({ error: 'Title and body required.' });
    const id = Date.now();
    if (imageBase64) await kv.set(K('ann:img:' + id), imageBase64, { ex: 60 * 60 * 24 * 365 });
    const list = (await kv.get(K('portal:announcements'))) || [];
    list.unshift({ id, title, body, pinned: !!pinned, hasImage: !!imageBase64, postedAt: nowISO() });
    if (list.length > 50) list.splice(50);
    await kv.set(K('portal:announcements'), list);
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

app.get('/api/portal/announcements/:id/image', async (req, res) => {
  try {
    // Try prefixed key first; fall back to unprefixed for images posted before Jun 24 namespace migration
    let b64 = await kv.get(K('ann:img:' + req.params.id));
    if (!b64) b64 = await kv.get('ann:img:' + req.params.id);
    if (!b64) return res.status(404).send('Not found');
    // Strip data URL prefix if present
    const match = String(b64).match(/^data:([^;]+);base64,(.+)$/);
    let contentType = 'image/jpeg';
    if (match) { contentType = match[1]; b64 = match[2]; }
    res.setHeader('Content-Type', contentType);
    res.setHeader('Cache-Control', 'public, max-age=31536000');
    res.send(Buffer.from(String(b64), 'base64'));
  } catch (e) { res.status(500).send('Server error: ' + e.message); }
});

app.delete('/api/portal/announcements/:id', requireAdmin, async (req, res) => {
  try {
    const id   = parseInt(req.params.id);
    const list = (await kv.get(K('portal:announcements'))) || [];
    await kv.set(K('portal:announcements'), list.filter(a => a.id !== id));
    await kv.del(K('ann:img:' + id));
    res.json({ ok: true });
  } catch { res.status(500).json({ error: 'Server error.' }); }
});

// ── CRM LEAD FORWARDING ─────────────────────────────────────────────────────
// Every captured lead must also reach the Bethel-CRM capture-lead webhook
// (see CLAUDE.md). CRM_WEBHOOK_URL = https://<crm-site>.netlify.app/.netlify/functions/capture-lead

const CRM_WEBHOOK_URL = process.env.CRM_WEBHOOK_URL || '';

function mapFuente(utmSource) {
  const s = (utmSource || '').toLowerCase();
  if (/facebook|fb|meta|instagram|ig/.test(s)) return 'meta_ads';
  if (/google|adwords/.test(s))                return 'google_ads';
  return 'organico';
}

async function forwardLeadToCRM(lead) {
  const payload = {
    nombre:         lead.nombre,
    telefono:       lead.telefono || '',
    email:          lead.email || undefined,
    fuente:         lead.fuente,
    campana:        lead.campana || undefined,
    landing_origen: 'bethel-main',
  };
  try {
    if (!CRM_WEBHOOK_URL)  throw new Error('CRM_WEBHOOK_URL not configured');
    if (!payload.telefono) throw new Error('missing telefono (required by CRM)');
    const r = await fetch(CRM_WEBHOOK_URL, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(payload),
    });
    if (!r.ok) throw new Error('CRM responded ' + r.status);
  } catch (e) {
    // Never lose a lead: queue anything the CRM didn't accept for manual review
    try {
      const list = (await kv.get(K('crm:unsent'))) || [];
      list.unshift({ ...payload, error: e.message, at: nowISO() });
      await kv.set(K('crm:unsent'), list.slice(0, 500));
    } catch {}
  }
}

// ── PUBLIC FORM SUBMISSIONS ──────────────────────────────────────────────────

// POST /api/join  –  agent application from landing page
app.post('/api/join', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, state, licensed, utmSource, utmCampaign } = req.body;
    if (!firstName || !email) return res.status(400).json({ error: 'Name and email are required.' });
    const entry = { firstName, lastName, email, phone, state, licensed, submittedAt: nowISO() };
    const list  = (await kv.get(K('join:submissions'))) || [];
    list.unshift(entry);
    await kv.set(K('join:submissions'), list.slice(0, 500));
    await forwardLeadToCRM({
      nombre:   [firstName, lastName].filter(Boolean).join(' '),
      telefono: phone,
      email,
      fuente:   mapFuente(utmSource),
      campana:  utmCampaign || 'formulario-unete',
    });
    const key = process.env.RESEND_API_KEY;
    if (key) {
      const resend = new Resend(key);
      await resend.emails.send({
        from: process.env.RESEND_FROM_EMAIL || 'noreply@bethelfinancialgroup.com',
        to:   ADMIN_EMAIL,
        subject: `New Agent Application — ${firstName} ${lastName} (${state || 'No state'})`,
        html: `<p><b>Name:</b> ${firstName} ${lastName}</p><p><b>Email:</b> ${email}</p><p><b>Phone:</b> ${phone || '—'}</p><p><b>State:</b> ${state || '—'}</p><p><b>Licensed:</b> ${licensed || '—'}</p><p><b>Submitted:</b> ${entry.submittedAt}</p>`,
      }).catch(() => {});
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// POST /api/contact  –  contact form from landing page
app.post('/api/contact', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, subject, message, utmSource, utmCampaign } = req.body;
    if (!firstName || !email || !message) return res.status(400).json({ error: 'Name, email, and message are required.' });
    const entry = { firstName, lastName, email, phone, subject, message, submittedAt: nowISO() };
    const list  = (await kv.get(K('contact:submissions'))) || [];
    list.unshift(entry);
    await kv.set(K('contact:submissions'), list.slice(0, 500));
    await forwardLeadToCRM({
      nombre:   [firstName, lastName].filter(Boolean).join(' '),
      telefono: phone,
      email,
      fuente:   mapFuente(utmSource),
      campana:  utmCampaign || 'formulario-contacto',
    });
    const key = process.env.RESEND_API_KEY;
    if (key) {
      const resend = new Resend(key);
      await resend.emails.send({
        from: process.env.RESEND_FROM_EMAIL || 'noreply@bethelfinancialgroup.com',
        to:   ADMIN_EMAIL,
        subject: `Contact Form — ${subject || 'General Inquiry'} from ${firstName} ${lastName}`,
        html: `<p><b>From:</b> ${firstName} ${lastName} (${email})</p><p><b>Phone:</b> ${phone || '—'}</p><p><b>Subject:</b> ${subject || '—'}</p><p><b>Message:</b></p><p>${message.replace(/\n/g,'<br>')}</p><p><b>Submitted:</b> ${entry.submittedAt}</p>`,
      }).catch(() => {});
    }
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// GET /api/submissions/join
app.get('/api/submissions/join', requireAdmin, async (req, res) => {
  try { res.json((await kv.get(K('join:submissions'))) || []); }
  catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// GET /api/submissions/contact
app.get('/api/submissions/contact', requireAdmin, async (req, res) => {
  try { res.json((await kv.get(K('contact:submissions'))) || []); }
  catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// GET /api/submissions/crm-unsent  –  leads that could not be forwarded to the CRM
app.get('/api/submissions/crm-unsent', requireAdmin, async (req, res) => {
  try { res.json((await kv.get(K('crm:unsent'))) || []); }
  catch (e) { res.status(500).json({ error: 'Server error.' }); }
});

// ── MIGRATION IMPORT (one-time use) ─────────────────────────────────────────
// POST /api/admin/import  { resources: [...], announcements: [...] }
app.post('/api/admin/import', requireAdmin, async (req, res) => {
  try {
    const { resources, announcements } = req.body;
    if (resources?.length)      await kv.set(K('portal:resources'),     resources);
    if (announcements?.length)  await kv.set(K('portal:announcements'), announcements);
    res.json({ ok: true, resources: resources?.length || 0, announcements: announcements?.length || 0 });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

module.exports = app;
