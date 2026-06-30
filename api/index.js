const express   = require('express');
const cors      = require('cors');
const jwt       = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');
const { Resend } = require('resend');

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

// ── AUTH ────────────────────────────────────────────────────────────────────

app.post('/api/login', (req, res) => {
  const { email = '', password = '' } = req.body || {};
  if (email.toLowerCase() === ADMIN_EMAIL && password === ADMIN_PW && password)
    return res.json({ token: makeToken({ email: ADMIN_EMAIL, isAdmin: true }), isAdmin: true });
  res.status(401).json({ error: 'Invalid credentials.' });
});

app.get('/api/me', (req, res) => {
  const d = verifyToken((req.headers.authorization || '').replace('Bearer ', ''));
  if (!d) return res.status(403).json({ error: 'Unauthorized' });
  res.json({ email: d.email, isAdmin: !!d.isAdmin });
});

// ── RESOURCES ───────────────────────────────────────────────────────────────

app.get('/api/portal/resources', async (req, res) => {
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

app.get('/api/portal/announcements', async (req, res) => {
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
    let b64 = await kv.get(K('ann:img:' + req.params.id));
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

// ── PUBLIC FORM SUBMISSIONS ──────────────────────────────────────────────────

// POST /api/join  –  agent application from landing page
app.post('/api/join', async (req, res) => {
  try {
    const { firstName, lastName, email, phone, state, licensed } = req.body;
    if (!firstName || !email) return res.status(400).json({ error: 'Name and email are required.' });
    const entry = { firstName, lastName, email, phone, state, licensed, submittedAt: nowISO() };
    const list  = (await kv.get(K('join:submissions'))) || [];
    list.unshift(entry);
    await kv.set(K('join:submissions'), list.slice(0, 500));
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
    const { firstName, lastName, email, subject, message } = req.body;
    if (!firstName || !email || !message) return res.status(400).json({ error: 'Name, email, and message are required.' });
    const entry = { firstName, lastName, email, subject, message, submittedAt: nowISO() };
    const list  = (await kv.get(K('contact:submissions'))) || [];
    list.unshift(entry);
    await kv.set(K('contact:submissions'), list.slice(0, 500));
    const key = process.env.RESEND_API_KEY;
    if (key) {
      const resend = new Resend(key);
      await resend.emails.send({
        from: process.env.RESEND_FROM_EMAIL || 'noreply@bethelfinancialgroup.com',
        to:   ADMIN_EMAIL,
        subject: `Contact Form — ${subject || 'General Inquiry'} from ${firstName} ${lastName}`,
        html: `<p><b>From:</b> ${firstName} ${lastName} (${email})</p><p><b>Subject:</b> ${subject || '—'}</p><p><b>Message:</b></p><p>${message.replace(/\n/g,'<br>')}</p><p><b>Submitted:</b> ${entry.submittedAt}</p>`,
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
