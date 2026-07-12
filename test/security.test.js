'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { createSession, verifySession, randomLicenseKey, signEnvelope } = require('../src/security');

test('session tokens verify only with the correct secret', () => {
  const token = createSession('a'.repeat(48), 60_000);
  assert.equal(verifySession(token, 'a'.repeat(48)), true);
  assert.equal(verifySession(token, 'b'.repeat(48)), false);
});

test('license keys use the expected readable format', () => {
  assert.match(randomLicenseKey(), /^RG-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/);
});

test('signed envelopes verify with Ed25519', () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const envelope = signEnvelope(privateKey, { valid: true, nonce: 'abc' });
  const payload = Buffer.from(envelope.payload, 'base64');
  assert.equal(crypto.verify(null, payload, publicKey, Buffer.from(envelope.signature, 'base64')), true);
});
