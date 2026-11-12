import assert from 'node:assert/strict';
import test from 'node:test';
import { InMemoryRateLimiter } from '../src/lib/rate-limiter.js';

test('rate limiter expires entries and keeps storage within its configured capacity', () => {
  const limiter = new InMemoryRateLimiter(2);
  assert.equal(limiter.consume('client-1', 1, 1_000, 0), undefined);
  assert.equal(limiter.consume('client-2', 1, 1_000, 0), undefined);
  assert.equal(limiter.consume('client-3', 1, 1_000, 0), 1);
  assert.equal(limiter.size, 2);

  assert.equal(limiter.consume('client-3', 1, 1_000, 1_000), undefined);
  assert.equal(limiter.size, 1);
  assert.equal(limiter.consume('client-1', 1, 1_000, 1_000), undefined);
  assert.equal(limiter.size, 2);
});

test('rate limiter rejects invalid storage capacities', () => {
  assert.throws(() => new InMemoryRateLimiter(0), RangeError);
});

test('rate limiter rejects new keys rather than evicting active counters at capacity', () => {
  const limiter = new InMemoryRateLimiter(1);
  assert.equal(limiter.consume('active-client', 1, 10_000, 0), undefined);
  assert.equal(limiter.consume('new-client', 1, 10_000, 0), 10);
  assert.equal(limiter.consume('active-client', 1, 10_000, 0), 10);
  assert.equal(limiter.size, 1);
});
