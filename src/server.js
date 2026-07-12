'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const express = require('express');
const multer = require('multer');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const { JsonStore } = require('./store');
const {
  ensureSecret,
  ensureSigningKeys,
  createSession,
  verifySession,
  safeEqualText,
  randomLicenseKey,
  signEnvelope
} = require('./security');
const { loginPage, implementerPage, adminPage } = require('./html');

const ROOT = path.resolve(__dirname, '..');
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const TMP_DIR = path.resolve(process.env.TMP_DIR || path.join(ROOT, 'tmp'));
const PORT = Number(process.env.PORT || 3000);
const NODE_ENV = process.env.NODE_ENV || 'development';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'change-me-now';

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

const store = new JsonStore(path.join(DATA_DIR, 'database.json'));
const sessionSecret = ensureSecret(DATA_DIR, process.env.SESSION_SECRET);
const signingKeys = ensureSigningKeys(DATA_DIR);

if (ADMIN_PASSWORD === 'change-me-now') {
  console.warn('[RailGuard] WARNING: ADMIN_PASSWORD is using the development default. Set it before public deployment.');
}

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cookieParser());
app.use(express.urlencoded({ extended: false, limit: '128kb' }));
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(ROOT, 'public'), { maxAge: NODE_ENV === 'production' ? '1h' : 0 }));

app.use((req, res, next) => {
  let csrf = req.cookies.rg_csrf;
  if (!csrf || !/^[A-Za-z0-9_-]{20,100}$/.test(csrf)) {
    csrf = crypto.randomBytes(24).toString('base64url');
    res.cookie('rg_csrf', csrf, cookieOptions(false));
  }
  req.csrfToken = csrf;
  req.isAdmin = verifySession(req.cookies.rg_session, sessionSecret);
  next();
});

const loginLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 20 },
  fileFilter: (_req, file, callback) => {
    const allowed = file.originalname.toLowerCase().endsWith('.jar');
    callback(allowed ? null : new Error('Only .jar files are accepted.'), allowed);
  }
});

function cookieOptions(httpOnly = true) {
  return {
    httpOnly,
    sameSite: 'strict',
    secure: NODE_ENV === 'production',
    path: '/',
    maxAge: 12 * 60 * 60 * 1000
  };
}

function requireAdmin(req, res, next) {
  if (!req.isAdmin) return res.redirect('/admin/login');
  next();
}

function requireCsrf(req, res, next) {
  const supplied = req.body?._csrf || req.get('x-csrf-token');
  if (!supplied || !safeEqualText(supplied, req.csrfToken)) {
    return res.status(403).send('Invalid CSRF token. Reload the page and try again.');
  }
  next();
}

function baseUrl(req) {
  if (process.env.PUBLIC_BASE_URL) return process.env.PUBLIC_BASE_URL.replace(/\/+$/, '');
  if (process.env.RAILWAY_PUBLIC_DOMAIN) return `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`;
  return `${req.protocol}://${req.get('host')}`;
}

function noticeFromQuery(req) {
  if (req.query.ok) return { type: 'success', text: String(req.query.ok).slice(0, 220) };
  if (req.query.error) return { type: 'error', text: String(req.query.error).slice(0, 220) };
  return null;
}

function redirectNotice(res, target, type, text) {
  const separator = target.includes('?') ? '&' : '?';
  res.redirect(`${target}${separator}${type}=${encodeURIComponent(text)}`);
}

function clampInt(value, min, max, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
}

function normalizeSlug(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '');
}

function normalizeLicenseKey(value) {
  return String(value || '').trim().toUpperCase();
}

function keyHash(key) {
  return crypto.createHash('sha256').update(normalizeLicenseKey(key)).digest('hex');
}

function audit(data, action, details = {}) {
  data.audit.push({ id: crypto.randomUUID(), action, details, at: Date.now() });
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'railguard', version: '1.0.1' });
});

app.get('/admin/login', (req, res) => {
  if (req.isAdmin) return res.redirect('/');
  res.send(loginPage(req.csrfToken));
});

app.post('/admin/login', loginLimiter, requireCsrf, (req, res) => {
  if (!safeEqualText(req.body.password || '', ADMIN_PASSWORD)) {
    return res.status(401).send(loginPage(req.csrfToken, 'Incorrect password.'));
  }
  res.cookie('rg_session', createSession(sessionSecret), cookieOptions(true));
  res.redirect('/');
});

app.post('/admin/logout', requireCsrf, (req, res) => {
  res.clearCookie('rg_session', { path: '/' });
  res.redirect('/admin/login');
});

app.get('/', requireAdmin, (req, res) => {
  const data = store.read();
  res.send(implementerPage({
    csrf: req.csrfToken,
    products: data.products,
    publicBaseUrl: baseUrl(req),
    publicKeyB64: signingKeys.publicKeyB64,
    notice: noticeFromQuery(req)
  }));
});

app.get('/admin', requireAdmin, (req, res) => {
  const data = store.read();
  res.send(adminPage({
    csrf: req.csrfToken,
    products: data.products,
    licenses: data.licenses,
    activations: data.activations,
    baseUrl: baseUrl(req),
    notice: noticeFromQuery(req)
  }));
});

app.post('/admin/products', requireAdmin, requireCsrf, async (req, res, next) => {
  try {
    const name = String(req.body.name || '').trim().slice(0, 80);
    const slug = normalizeSlug(req.body.slug);
    if (!name || !slug) return redirectNotice(res, '/admin', 'error', 'Product name and slug are required.');
    await store.mutate((data) => {
      if (data.products.some((p) => p.slug === slug)) throw new Error('That product slug already exists.');
      const product = {
        id: crypto.randomUUID(),
        name,
        slug,
        active: true,
        maxActivations: clampInt(req.body.max_activations, 1, 1000, 1),
        maxOfflineHours: clampInt(req.body.max_offline_hours, 0, 720, 24),
        createdAt: Date.now()
      };
      data.products.push(product);
      audit(data, 'product.create', { productId: product.id, slug });
    });
    redirectNotice(res, '/admin', 'ok', `Product “${name}” created.`);
  } catch (error) {
    if (error.message.includes('slug')) return redirectNotice(res, '/admin', 'error', error.message);
    next(error);
  }
});

app.post('/admin/products/:id/toggle', requireAdmin, requireCsrf, async (req, res, next) => {
  try {
    const result = await store.mutate((data) => {
      const product = data.products.find((p) => p.id === req.params.id);
      if (!product) throw new Error('Product not found.');
      product.active = !product.active;
      audit(data, 'product.toggle', { productId: product.id, active: product.active });
      return product.active;
    });
    redirectNotice(res, '/admin', 'ok', `Product ${result ? 'enabled' : 'disabled'}.`);
  } catch (error) { next(error); }
});

app.post('/admin/licenses', requireAdmin, requireCsrf, async (req, res, next) => {
  try {
    const customer = String(req.body.customer || '').trim().slice(0, 120);
    const expiresAt = req.body.expires_at ? Date.parse(`${req.body.expires_at}T23:59:59.999Z`) : null;
    if (expiresAt && (!Number.isFinite(expiresAt) || expiresAt <= Date.now())) {
      return redirectNotice(res, '/admin', 'error', 'Expiration must be a future date.');
    }
    const license = await store.mutate((data) => {
      const product = data.products.find((p) => p.id === req.body.product_id && p.active);
      if (!product) throw new Error('Choose an active product.');
      let key;
      do { key = randomLicenseKey(); } while (data.licenses.some((l) => l.key === key));
      const maxOverrideRaw = String(req.body.max_activations || '').trim();
      const created = {
        id: crypto.randomUUID(),
        productId: product.id,
        key,
        customer,
        active: true,
        expiresAt,
        maxActivations: maxOverrideRaw ? clampInt(maxOverrideRaw, 1, 1000, product.maxActivations) : null,
        createdAt: Date.now()
      };
      data.licenses.push(created);
      audit(data, 'license.create', { licenseId: created.id, productId: product.id, customer });
      return created;
    });
    redirectNotice(res, '/admin', 'ok', `License created: ${license.key}`);
  } catch (error) {
    if (error.message.includes('active product')) return redirectNotice(res, '/admin', 'error', error.message);
    next(error);
  }
});

app.post('/admin/licenses/:id/toggle', requireAdmin, requireCsrf, async (req, res, next) => {
  try {
    const active = await store.mutate((data) => {
      const license = data.licenses.find((l) => l.id === req.params.id);
      if (!license) throw new Error('License not found.');
      license.active = !license.active;
      audit(data, 'license.toggle', { licenseId: license.id, active: license.active });
      return license.active;
    });
    redirectNotice(res, '/admin', 'ok', `License ${active ? 'restored' : 'revoked'}.`);
  } catch (error) { next(error); }
});

app.post('/admin/licenses/:id/reset', requireAdmin, requireCsrf, async (req, res, next) => {
  try {
    const removed = await store.mutate((data) => {
      const license = data.licenses.find((l) => l.id === req.params.id);
      if (!license) throw new Error('License not found.');
      const before = data.activations.length;
      data.activations = data.activations.filter((a) => a.licenseId !== license.id);
      audit(data, 'license.reset_activations', { licenseId: license.id, removed: before - data.activations.length });
      return before - data.activations.length;
    });
    redirectNotice(res, '/admin', 'ok', `Removed ${removed} activation${removed === 1 ? '' : 's'}.`);
  } catch (error) { next(error); }
});

app.post('/patch', requireAdmin, upload.single('plugin'), requireCsrf, async (req, res, next) => {
  const inputPath = req.file?.path;
  let outputPath;
  try {
    if (!req.file) throw new Error('Choose a plugin JAR.');
    const fileHeader = fs.readFileSync(inputPath).subarray(0, 4);
    if (fileHeader.length < 4 || fileHeader[0] !== 0x50 || fileHeader[1] !== 0x4b) throw new Error('The uploaded file is not a valid JAR/ZIP archive.');

    const data = store.read();
    const product = data.products.find((p) => p.id === req.body.product_id && p.active);
    if (!product) throw new Error('Choose an active product.');

    const apiUrl = String(req.body.api_url || '').trim().replace(/\/+$/, '');
    if (!/^https?:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/.*)?$/.test(apiUrl)) throw new Error('Enter a valid HTTP or HTTPS license-server URL.');
    if (NODE_ENV === 'production' && !apiUrl.startsWith('https://')) throw new Error('Production builds must use an HTTPS license-server URL.');

    let embeddedKey = '';
    if (req.body.key_mode === 'embedded') {
      embeddedKey = normalizeLicenseKey(req.body.embedded_key);
      const license = data.licenses.find((l) => l.productId === product.id && l.key === embeddedKey && l.active);
      if (!license) throw new Error('The embedded key is not an active license for this product.');
    }

    const graceHours = Math.min(clampInt(req.body.grace_hours, 0, 720, 24), product.maxOfflineHours);
    const timeoutMs = clampInt(req.body.timeout_ms, 1000, 15000, 4000);
    const originalBase = path.basename(req.file.originalname, path.extname(req.file.originalname)).replace(/[^A-Za-z0-9._-]+/g, '-').slice(0, 100) || 'plugin';
    outputPath = path.join(TMP_DIR, `${crypto.randomUUID()}-${originalBase}-licensed.jar`);

    const patchInfo = await runPatcher({
      inputPath,
      outputPath,
      productId: product.id,
      apiUrl,
      publicKeyB64: signingKeys.publicKeyB64,
      embeddedKey,
      graceHours,
      timeoutMs
    });

    await store.mutate((db) => {
      audit(db, 'plugin.patch', {
        productId: product.id,
        originalName: req.file.originalname,
        originalMain: patchInfo.original_main,
        wrapperMain: patchInfo.wrapper_main,
        embedded: Boolean(embeddedKey)
      });
    });

    const downloadName = `${originalBase}-licensed.jar`;
    res.download(outputPath, downloadName, (error) => {
      safeUnlink(inputPath);
      safeUnlink(outputPath);
      if (error && !res.headersSent) next(error);
    });
  } catch (error) {
    safeUnlink(inputPath);
    safeUnlink(outputPath);
    next(error);
  }
});

app.post('/api/v1/validate', apiLimiter, async (req, res, next) => {
  try {
    const productId = String(req.body.product_id || '').trim().slice(0, 100);
    const licenseKey = normalizeLicenseKey(req.body.license_key).slice(0, 120);
    const instanceId = String(req.body.instance_id || '').trim().slice(0, 100);
    const nonce = String(req.body.nonce || '').trim().slice(0, 100);
    const pluginVersion = String(req.body.plugin_version || 'unknown').slice(0, 80);
    const serverVersion = String(req.body.server_version || 'unknown').slice(0, 160);
    const requestedGrace = clampInt(req.body.grace_hours, 0, 720, 0);

    if (!productId || !licenseKey || !instanceId || !nonce || !/^[A-Za-z0-9._:-]{8,100}$/.test(instanceId)) {
      return res.status(400).json({ error: 'Malformed validation request.' });
    }

    const now = Date.now();
    const decision = await store.mutate((data) => {
      const base = {
        valid: false,
        code: 'INVALID',
        message: 'License validation failed.',
        product_id: productId,
        instance_id: instanceId,
        nonce,
        key_hash: keyHash(licenseKey),
        issued_at: now,
        lease_expires_at: now + 15 * 60 * 1000,
        offline_until: now
      };
      const product = data.products.find((p) => p.id === productId);
      if (!product || !product.active) return { ...base, code: 'PRODUCT_DISABLED', message: 'This product is unavailable.' };
      const license = data.licenses.find((l) => l.productId === product.id && l.key === licenseKey);
      if (!license) return { ...base, code: 'KEY_NOT_FOUND', message: 'The license key is invalid.' };
      if (!license.active) return { ...base, code: 'REVOKED', message: 'The license has been revoked.' };
      if (license.expiresAt && license.expiresAt < now) return { ...base, code: 'EXPIRED', message: 'The license has expired.' };

      const limit = license.maxActivations ?? product.maxActivations;
      let activation = data.activations.find((a) => a.licenseId === license.id && a.instanceId === instanceId);
      if (!activation) {
        const activeCount = data.activations.filter((a) => a.licenseId === license.id).length;
        if (activeCount >= limit) return { ...base, code: 'ACTIVATION_LIMIT', message: 'The activation limit has been reached.' };
        activation = {
          id: crypto.randomUUID(),
          licenseId: license.id,
          instanceId,
          createdAt: now,
          lastSeenAt: now,
          pluginVersion,
          serverVersion,
          ipHash: crypto.createHash('sha256').update(`${req.ip}|${sessionSecret}`).digest('hex').slice(0, 24)
        };
        data.activations.push(activation);
        audit(data, 'activation.create', { licenseId: license.id, instanceId });
      } else {
        activation.lastSeenAt = now;
        activation.pluginVersion = pluginVersion;
        activation.serverVersion = serverVersion;
      }

      const graceHours = Math.min(requestedGrace, product.maxOfflineHours);
      let offlineUntil = now + graceHours * 60 * 60 * 1000;
      if (license.expiresAt) offlineUntil = Math.min(offlineUntil, license.expiresAt);
      return {
        ...base,
        valid: true,
        code: 'OK',
        message: 'License accepted.',
        license_id: license.id,
        lease_expires_at: now + 15 * 60 * 1000,
        offline_until: offlineUntil,
        expires_at: license.expiresAt
      };
    });

    res.set('Cache-Control', 'no-store');
    res.json(signEnvelope(signingKeys.privateKey, decision));
  } catch (error) { next(error); }
});

async function runPatcher({ inputPath, outputPath, productId, apiUrl, publicKeyB64, embeddedKey, graceHours, timeoutMs }) {
  const classPath = path.join(ROOT, 'java-build');
  const args = [
    '-cp', classPath,
    'dev.railguard.patcher.JarPatcher',
    inputPath,
    outputPath,
    productId,
    apiUrl,
    publicKeyB64,
    Buffer.from(embeddedKey, 'utf8').toString('base64'),
    String(graceHours),
    String(timeoutMs),
    crypto.randomUUID()
  ];
  return new Promise((resolve, reject) => {
    const child = spawn('java', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('Plugin patching timed out.'));
    }, 30_000);
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (error) => { clearTimeout(timer); reject(error); });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error((stderr || stdout || `Patcher exited with code ${code}`).trim().slice(0, 800)));
      try { resolve(JSON.parse(stdout.trim())); } catch { reject(new Error('Patcher returned an unreadable result.')); }
    });
  });
}

function safeUnlink(file) {
  if (!file) return;
  fs.rm(file, { force: true }, () => {});
}

app.use((error, req, res, _next) => {
  console.error(error);
  const message = error instanceof multer.MulterError
    ? (error.code === 'LIMIT_FILE_SIZE' ? 'The JAR exceeds the 50 MB upload limit.' : error.message)
    : (error.message || 'Unexpected server error.');
  if (req.path === '/patch' && !res.headersSent) return redirectNotice(res, '/', 'error', message);
  if (!res.headersSent) res.status(500).send(`RailGuard error: ${String(message).replace(/[<>]/g, '')}`);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[RailGuard] Listening on 0.0.0.0:${PORT}`);
  console.log(`[RailGuard] Data directory: ${DATA_DIR}`);
});
