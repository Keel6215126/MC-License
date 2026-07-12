'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function ensureSecret(dataDir, envValue) {
  if (envValue && envValue.length >= 32) return envValue;
  const file = path.join(dataDir, 'session-secret');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
  const secret = crypto.randomBytes(48).toString('base64url');
  fs.mkdirSync(dataDir, { recursive: true });
  fs.writeFileSync(file, `${secret}\n`, { mode: 0o600 });
  return secret;
}

function ensureSigningKeys(dataDir) {
  const privatePath = path.join(dataDir, 'ed25519-private.pem');
  const publicPath = path.join(dataDir, 'ed25519-public.pem');
  if (!fs.existsSync(privatePath) || !fs.existsSync(publicPath)) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
    fs.mkdirSync(dataDir, { recursive: true });
    fs.writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
    fs.writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o644 });
  }
  const privateKey = crypto.createPrivateKey(fs.readFileSync(privatePath));
  const publicKey = crypto.createPublicKey(fs.readFileSync(publicPath));
  const publicDer = publicKey.export({ type: 'spki', format: 'der' });
  return { privateKey, publicKey, publicKeyB64: publicDer.toString('base64') };
}

function createSession(secret, lifetimeMs = 12 * 60 * 60 * 1000) {
  const payload = Buffer.from(JSON.stringify({ exp: Date.now() + lifetimeMs, nonce: crypto.randomUUID() })).toString('base64url');
  const signature = crypto.createHmac('sha256', secret).update(payload).digest('base64url');
  return `${payload}.${signature}`;
}

function verifySession(token, secret) {
  try {
    const [payload, signature] = String(token || '').split('.');
    if (!payload || !signature) return false;
    const expected = crypto.createHmac('sha256', secret).update(payload).digest();
    const supplied = Buffer.from(signature, 'base64url');
    if (expected.length !== supplied.length || !crypto.timingSafeEqual(expected, supplied)) return false;
    const parsed = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return Number.isFinite(parsed.exp) && parsed.exp > Date.now();
  } catch {
    return false;
  }
}

function safeEqualText(a, b) {
  const left = crypto.createHash('sha256').update(String(a)).digest();
  const right = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(left, right);
}

function randomLicenseKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const groups = [];
  for (let g = 0; g < 4; g += 1) {
    let group = '';
    for (let i = 0; i < 5; i += 1) group += alphabet[crypto.randomInt(alphabet.length)];
    groups.push(group);
  }
  return `RG-${groups.join('-')}`;
}

function signEnvelope(privateKey, payloadObject) {
  const payloadBytes = Buffer.from(JSON.stringify(payloadObject), 'utf8');
  const signature = crypto.sign(null, payloadBytes, privateKey);
  return {
    payload: payloadBytes.toString('base64'),
    signature: signature.toString('base64')
  };
}

module.exports = {
  ensureSecret,
  ensureSigningKeys,
  createSession,
  verifySession,
  safeEqualText,
  randomLicenseKey,
  signEnvelope
};
