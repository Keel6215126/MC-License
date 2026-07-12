'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const express = require('express');
const multer = require('multer');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const { implementerPage, licenseCheckPage } = require('./html');

const ROOT = path.resolve(__dirname, '..');
const TMP_DIR = path.resolve(process.env.TMP_DIR || path.join(ROOT, 'tmp'));
const PORT = Number(process.env.PORT || 3000);
const MCL_LIBRARY_JAR = path.resolve(process.env.MCL_LIBRARY_JAR || path.join(ROOT, 'vendor', 'mc-license-library-1.5.1.jar'));

fs.mkdirSync(TMP_DIR, { recursive: true });

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: false, limit: '64kb' }));
app.use(express.static(path.join(ROOT, 'public'), { maxAge: process.env.NODE_ENV === 'production' ? '1h' : 0 }));

const implementLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false
});

const upload = multer({
  dest: TMP_DIR,
  limits: { fileSize: 50 * 1024 * 1024, files: 1, fields: 4 },
  fileFilter: (_req, file, callback) => {
    const allowed = file.originalname.toLowerCase().endsWith('.jar');
    callback(allowed ? null : new Error('Only Minecraft plugin .jar files are accepted.'), allowed);
  }
});

function noticeFromQuery(req) {
  if (req.query.error) return { type: 'error', text: String(req.query.error).slice(0, 240) };
  return null;
}

function redirectError(res, message) {
  res.redirect(`/?error=${encodeURIComponent(String(message).slice(0, 240))}`);
}

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'mc-license-implementer', library: '1.5.1' });
});

app.get('/', (req, res) => {
  res.send(implementerPage({ notice: noticeFromQuery(req) }));
});

app.get('/license-check', (_req, res) => {
  res.send(licenseCheckPage());
});

app.post('/implement', implementLimiter, upload.single('plugin'), async (req, res, next) => {
  const inputPath = req.file?.path;
  let outputPath;

  try {
    if (!req.file) throw new Error('Choose a Minecraft plugin JAR.');

    const pluginId = String(req.body.plugin_id || '').trim();
    if (!/^[A-Za-z0-9]{8}$/.test(pluginId)) {
      throw new Error('The MC License plugin ID must be exactly 8 letters and numbers.');
    }

    const fileHeader = fs.readFileSync(inputPath).subarray(0, 4);
    if (fileHeader.length < 4 || fileHeader[0] !== 0x50 || fileHeader[1] !== 0x4b) {
      throw new Error('The uploaded file is not a valid JAR/ZIP archive.');
    }

    if (!fs.existsSync(MCL_LIBRARY_JAR)) {
      throw new Error('MC License library 1.5.1 is missing from this deployment.');
    }

    const originalBase = path.basename(req.file.originalname, path.extname(req.file.originalname))
      .replace(/[^A-Za-z0-9._-]+/g, '-')
      .slice(0, 100) || 'plugin';

    outputPath = path.join(TMP_DIR, `${crypto.randomUUID()}-${originalBase}-mclicensed.jar`);

    await runPatcher({
      inputPath,
      outputPath,
      pluginId,
      libraryJar: MCL_LIBRARY_JAR
    });

    res.download(outputPath, `${originalBase}-mclicensed.jar`, (error) => {
      safeUnlink(inputPath);
      safeUnlink(outputPath);
      if (error && !res.headersSent) next(error);
    });
  } catch (error) {
    safeUnlink(inputPath);
    safeUnlink(outputPath);
    if (!res.headersSent) return redirectError(res, error.message || 'Could not implement MC License.');
    next(error);
  }
});

async function runPatcher({ inputPath, outputPath, pluginId, libraryJar }) {
  const classPath = path.join(ROOT, 'java-build');
  const args = [
    '-cp', classPath,
    'dev.railguard.patcher.JarPatcher',
    inputPath,
    outputPath,
    pluginId,
    libraryJar,
    crypto.randomUUID()
  ];

  return new Promise((resolve, reject) => {
    const child = spawn('java', args, { cwd: ROOT, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      reject(new Error('Plugin processing timed out.'));
    }, 30_000);

    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        return reject(new Error((stderr || stdout || `Patcher exited with code ${code}`).trim().slice(0, 800)));
      }
      try {
        resolve(JSON.parse(stdout.trim()));
      } catch {
        reject(new Error('The plugin processor returned an unreadable result.'));
      }
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

  if (req.path === '/implement' && !res.headersSent) return redirectError(res, message);
  if (!res.headersSent) res.status(500).send(`MC License Implementer error: ${String(message).replace(/[<>]/g, '')}`);
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[MC License Implementer] Listening on 0.0.0.0:${PORT}`);
  console.log(`[MC License Implementer] Using MC License library 1.5.1 from ${MCL_LIBRARY_JAR}`);
});
