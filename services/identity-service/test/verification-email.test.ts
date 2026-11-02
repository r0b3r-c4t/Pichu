import assert from 'node:assert/strict';
import test from 'node:test';
import { createVerificationEmail } from '../src/email/verification-email.js';

test('normalizes whitespace in plaintext names and keeps HTML escaping', () => {
  const email = createVerificationEmail({
    name: ' Ada \t\n <Lovelace> ',
    verificationUrl: 'http://localhost:3000/verify-email',
    token: 'opaque-token',
  });

  assert.match(email.text, /^Hello Ada <Lovelace>,\n\n/);
  assert.match(email.html, /Hello  Ada \t\n &lt;Lovelace&gt; /);
});
