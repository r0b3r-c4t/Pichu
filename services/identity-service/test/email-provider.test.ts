import assert from 'node:assert/strict';
import test from 'node:test';
import { EmailProviderError } from '../src/email/email-provider.js';
import { ResendEmailProvider, type ResendEmailClient } from '../src/email/resend-email.provider.js';

function createClient(response: { data: { id?: unknown } | null; error: unknown | null }) {
  let payload: unknown;
  const client: ResendEmailClient = {
    emails: {
      send: async (nextPayload) => {
        payload = nextPayload;
        return response;
      },
    },
  };

  return {
    client,
    get payload() {
      return payload;
    },
  };
}

test('sends an email with the configured sender and message fields', async () => {
  const fake = createClient({ data: { id: 'email_123' }, error: null });
  const provider = new ResendEmailProvider(
    {
      apiKey: 're_sensitive_test_key',
      fromEmail: 'no-reply@example.com',
      fromName: 'PICHU',
    },
    fake.client,
  );

  const result = await provider.send({
    to: 'user@example.com',
    subject: 'Verify your email',
    html: '<p>Verification</p>',
    text: 'Verification',
  });

  assert.deepEqual(result, { id: 'email_123' });
  assert.deepEqual(fake.payload, {
    from: 'PICHU <no-reply@example.com>',
    to: 'user@example.com',
    subject: 'Verify your email',
    html: '<p>Verification</p>',
    text: 'Verification',
  });
});

test('does not include text when it is omitted', async () => {
  const fake = createClient({ data: { id: 'email_456' }, error: null });
  const provider = new ResendEmailProvider(
    { apiKey: 're_sensitive_test_key', fromEmail: 'no-reply@example.com', fromName: 'PICHU' },
    fake.client,
  );

  await provider.send({ to: 'user@example.com', subject: 'Notice', html: '<p>Notice</p>' });

  assert.deepEqual(fake.payload, {
    from: 'PICHU <no-reply@example.com>',
    to: 'user@example.com',
    subject: 'Notice',
    html: '<p>Notice</p>',
  });
});

test('sanitizes provider errors and does not expose the API key', async () => {
  const apiKey = 're_sensitive_test_key';
  const fake = createClient({ data: null, error: { message: `invalid key ${apiKey}` } });
  const provider = new ResendEmailProvider(
    { apiKey, fromEmail: 'no-reply@example.com', fromName: 'PICHU' },
    fake.client,
  );

  await assert.rejects(
    provider.send({ to: 'user@example.com', subject: 'Notice', html: '<p>Notice</p>' }),
    (error: unknown) => {
      assert.ok(error instanceof EmailProviderError);
      assert.equal(error.message, 'Email delivery failed');
      assert.equal(error.message.includes(apiKey), false);
      assert.equal(error.providerCode, undefined);
      assert.equal(error.cause !== undefined, true);
      return true;
    },
  );
});

test('preserves a safe provider error code without exposing its message', async () => {
  const fake = createClient({
    data: null,
    error: { name: 'validation_error', message: 'secret details' },
  });
  const provider = new ResendEmailProvider(
    { apiKey: 're_sensitive_test_key', fromEmail: 'no-reply@example.com', fromName: 'PICHU' },
    fake.client,
  );

  await assert.rejects(
    provider.send({ to: 'user@example.com', subject: 'Notice', html: '<p />' }),
    (error: unknown) => {
      assert.ok(error instanceof EmailProviderError);
      assert.equal(error.providerCode, 'VALIDATION_ERROR');
      assert.equal(error.message.includes('secret details'), false);
      return true;
    },
  );
});

test('sanitizes thrown provider errors', async () => {
  const apiKey = 're_sensitive_test_key';
  const client: ResendEmailClient = {
    emails: {
      send: async () => {
        throw new Error(`request failed with ${apiKey}`);
      },
    },
  };
  const provider = new ResendEmailProvider(
    { apiKey, fromEmail: 'no-reply@example.com', fromName: 'PICHU' },
    client,
  );

  await assert.rejects(
    provider.send({ to: 'user@example.com', subject: 'Notice', html: '<p>Notice</p>' }),
    (error: unknown) => {
      assert.ok(error instanceof EmailProviderError);
      assert.equal(error.message.includes(apiKey), false);
      return true;
    },
  );
});

test('rejects a successful provider response without a non-empty ID', async () => {
  for (const data of [null, {}, { id: '' }, { id: '   ' }, { id: 123 }]) {
    const fake = createClient({ data, error: null });
    const provider = new ResendEmailProvider(
      { apiKey: 're_sensitive_test_key', fromEmail: 'no-reply@example.com', fromName: 'PICHU' },
      fake.client,
    );

    await assert.rejects(
      provider.send({ to: 'user@example.com', subject: 'Notice', html: '<p>Notice</p>' }),
      (error: unknown) => error instanceof EmailProviderError,
    );
  }
});

test('rejects sender names containing CR or LF without exposing configuration', () => {
  const apiKey = 're_sensitive_test_key';

  for (const fromName of ['PICHU\r', 'PICHU\n', `PICHU\r\n${apiKey}`]) {
    assert.throws(
      () =>
        new ResendEmailProvider({
          apiKey,
          fromEmail: 'no-reply@example.com',
          fromName,
        }),
      (error: unknown) => {
        assert.ok(error instanceof EmailProviderError);
        assert.equal(error.message, 'Invalid email provider configuration');
        assert.equal(error.message.includes(apiKey), false);
        return true;
      },
    );
  }
});

test('rejects invalid sender email addresses including CRLF', () => {
  for (const fromEmail of ['', 'not-an-email', 'sender@example.com\r\nBcc: victim@example.com']) {
    assert.throws(
      () =>
        new ResendEmailProvider({
          apiKey: 're_sensitive_test_key',
          fromEmail,
          fromName: 'PICHU',
        }),
      (error: unknown) =>
        error instanceof EmailProviderError &&
        error.message === 'Invalid email provider configuration',
    );
  }
});
