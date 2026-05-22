import express from 'express';
import cors from 'cors';
import crypto from 'crypto';

const app = express();
const PORT = process.env.BACKEND_PORT || 3000;

const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:3000',
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({ origin: allowedOrigins, credentials: true }));
app.use(express.json());

// ── In-memory data ──────────────────────────────────────────────────────────

const apiKeys = [
  {
    id: 'key_live_a1b2c3d4e5f6',
    name: 'Production API',
    prefix: 'sk_live_...f6',
    created: '2026-03-01T10:00:00Z',
    lastUsed: '2026-04-05T14:30:00Z',
    status: 'active',
    permissions: ['read', 'write'],
    rateLimit: 1000,
    usage: { today: 847, thisMonth: 23500, total: 142000 },
    environment: 'production'
  },
  {
    id: 'key_test_g7h8i9j0k1l2',
    name: 'Staging API',
    prefix: 'sk_test_...l2',
    created: '2026-03-15T08:00:00Z',
    lastUsed: '2026-04-05T12:15:00Z',
    status: 'active',
    permissions: ['read', 'write', 'admin'],
    rateLimit: 5000,
    usage: { today: 2341, thisMonth: 45200, total: 89000 },
    environment: 'staging'
  },
  {
    id: 'key_test_m3n4o5p6q7r8',
    name: 'Development API',
    prefix: 'sk_test_...r8',
    created: '2026-02-20T16:00:00Z',
    lastUsed: '2026-04-04T09:45:00Z',
    status: 'active',
    permissions: ['read'],
    rateLimit: 10000,
    usage: { today: 156, thisMonth: 3200, total: 12000 },
    environment: 'development'
  },
  {
    id: 'key_live_s9t0u1v2w3x4',
    name: 'Analytics Service',
    prefix: 'sk_live_...x4',
    created: '2026-01-10T12:00:00Z',
    lastUsed: '2026-04-03T18:20:00Z',
    status: 'revoked',
    permissions: ['read'],
    rateLimit: 500,
    usage: { today: 0, thisMonth: 0, total: 67000 },
    environment: 'production'
  }
];

const usageLogs = [];
for (let i = 23; i >= 0; i--) {
  const hour = new Date(Date.now() - i * 3600000);
  usageLogs.push({
    hour: hour.toISOString(),
    key_live_a1b2c3d4e5f6: Math.floor(Math.random() * 50) + 20,
    key_test_g7h8i9j0k1l2: Math.floor(Math.random() * 120) + 50,
    key_test_m3n4o5p6q7r8: Math.floor(Math.random() * 15) + 2,
    key_live_s9t0u1v2w3x4: 0
  });
}

const startTime = Date.now();

// ── Secret handling ───────────────────────────────────────────────────────────
// API key secrets are never stored in plaintext. We keep only a SHA-256 hash and
// the display prefix; the full secret is returned exactly once (on create/rotate)
// and can never be read back — matching the UI's "shown only once" promise.

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret).digest('hex');
}

// publicView returns a key object safe to send to any GET consumer: it strips the
// stored hash and never carries a plaintext secret.
function publicView(k) {
  const { keyHash, key, ...safe } = k;
  return safe;
}

// ── Auth (real signed HS256 JWT, no external dependency) ──────────────────────
const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change-me';

function signToken(payload, expiresInSec = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify({ ...payload, iat: now, exp: now + expiresInSec })).toString('base64url');
  const data = `${header}.${body}`;
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(data).digest('base64url');
  return `${data}.${sig}`;
}

function verifyToken(token) {
  const parts = (token || '').split('.');
  if (parts.length !== 3) return null;
  const [h, p, sig] = parts;
  const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${h}.${p}`).digest('base64url');
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let payload;
  try { payload = JSON.parse(Buffer.from(p, 'base64url').toString()); } catch { return null; }
  if (payload.exp && Math.floor(Date.now() / 1000) > payload.exp) return null;
  return payload;
}

// requireAuth rejects requests without a valid Bearer token.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Unauthorized', reason: 'INVALID_OR_MISSING_TOKEN' });
  }
  req.user = payload;
  next();
}

// ── Middleware: request logger ────────────────────────────────────────────────
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

// ── Routes ───────────────────────────────────────────────────────────────────

// POST /api/login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  if (email === 'admin@apikeys.dev' && password === 'admin123') {
    const user = { name: 'Admin', email: 'admin@apikeys.dev', role: 'owner' };
    return res.json({
      success: true,
      token: signToken({ sub: user.email, name: user.name, role: user.role }),
      user
    });
  }
  res.status(401).json({ error: 'Invalid credentials' });
});

// GET /api/keys
app.get('/api/keys', requireAuth, (_req, res) => {
  res.json(apiKeys.map(publicView));
});

// GET /api/keys/search
app.get('/api/keys/search', requireAuth, (req, res) => {
  const q = (req.query.q || '').toLowerCase();
  const results = apiKeys.filter(k => k.name.toLowerCase().includes(q));
  res.json(results.map(publicView));
});

// GET /api/keys/:id
app.get('/api/keys/:id', requireAuth, (req, res) => {
  const key = apiKeys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  res.json(publicView(key));
});

// POST /api/keys
app.post('/api/keys', requireAuth, (req, res) => {
  const { name, permissions = ['read'], environment = 'development', rateLimit = 1000 } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  const hex = crypto.randomBytes(16).toString('hex');
  const prefix = environment.startsWith('prod') ? 'sk_live' : 'sk_test';
  const id = `key_${environment.slice(0, 4)}_${hex.slice(0, 12)}`;
  const suffix = hex.slice(-2);
  const secret = `${prefix}_${hex}${crypto.randomBytes(8).toString('hex')}`;

  const newKey = {
    id,
    name,
    prefix: `${prefix}_...${suffix}`,
    created: new Date().toISOString(),
    lastUsed: null,
    status: 'active',
    permissions,
    rateLimit,
    usage: { today: 0, thisMonth: 0, total: 0 },
    environment,
    keyHash: hashSecret(secret) // store only the hash — never the plaintext
  };

  apiKeys.push(newKey);
  // Return the secret exactly once; subsequent GETs never expose it.
  res.status(201).json({ ...publicView(newKey), key: secret });
});

// DELETE /api/keys/:id
app.delete('/api/keys/:id', requireAuth, (req, res) => {
  const key = apiKeys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  key.status = 'revoked';
  res.json(publicView(key));
});

// POST /api/keys/:id/rotate
app.post('/api/keys/:id/rotate', requireAuth, (req, res) => {
  const key = apiKeys.find(k => k.id === req.params.id);
  if (!key) return res.status(404).json({ error: 'Key not found' });
  const hex = crypto.randomBytes(24).toString('hex');
  const prefix = key.environment.startsWith('prod') ? 'sk_live' : 'sk_test';
  const secret = `${prefix}_${hex}`;
  key.keyHash = hashSecret(secret); // rotate the stored hash
  key.prefix = `${prefix}_...${hex.slice(-2)}`;
  key.lastUsed = new Date().toISOString();
  // Return the new secret exactly once.
  res.json({ ...publicView(key), key: secret });
});

// GET /api/keys/:id/usage
app.get('/api/keys/:id/usage', requireAuth, (req, res) => {
  const keyId = req.params.id;
  const data = usageLogs.map(entry => ({
    hour: entry.hour,
    requests: entry[keyId] ?? 0
  }));
  res.json(data);
});

// GET /api/usage/overview
app.get('/api/usage/overview', requireAuth, (_req, res) => {
  const active = apiKeys.filter(k => k.status === 'active');
  const totalToday = apiKeys.reduce((s, k) => s + k.usage.today, 0);
  const totalMonth = apiKeys.reduce((s, k) => s + k.usage.thisMonth, 0);
  res.json({
    totalKeys: apiKeys.length,
    activeKeys: active.length,
    totalRequestsToday: totalToday,
    totalRequestsMonth: totalMonth
  });
});

// GET /api/health
app.get('/api/health', (_req, res) => {
  res.json({ status: 'healthy', keys: apiKeys.length, uptime: Math.floor((Date.now() - startTime) / 1000) });
});

// POST /api/scan — no-op endpoint used by the attack tester for entropy detection demo.
// No rate limit is configured on this path so the WAF entropy check always runs first.
app.post('/api/scan', (_req, res) => {
  res.json({ ok: true });
});

// ── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, '127.0.0.1', () => {
  console.log(`[KeyVault Backend] Running on http://127.0.0.1:${PORT}`);
});
