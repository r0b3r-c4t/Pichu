interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const DEFAULT_MAX_ENTRIES = 10_000;
const CLEANUP_INTERVAL = 256;

export class InMemoryRateLimiter {
  private readonly entries = new Map<string, RateLimitEntry>();
  private requestsSinceCleanup = 0;
  private nextCapacityCleanupAt = 0;
  private capacityRetryAfterSeconds = 1;

  constructor(private readonly maxEntries = DEFAULT_MAX_ENTRIES) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) {
      throw new RangeError('Rate limiter storage capacity must be a positive integer');
    }
  }

  get size(): number {
    return this.entries.size;
  }

  consume(key: string, limit: number, windowMs: number, now = Date.now()): number | undefined {
    this.requestsSinceCleanup += 1;
    if (this.requestsSinceCleanup >= CLEANUP_INTERVAL) {
      this.removeExpired(now);
      this.requestsSinceCleanup = 0;
    }

    const current = this.entries.get(key);
    if (current && current.resetAt > now) {
      if (current.count >= limit) return this.retryAfterSeconds(current.resetAt, now);
      current.count += 1;
      return undefined;
    }

    if (current) this.entries.delete(key);
    if (this.entries.size >= this.maxEntries) {
      if (now >= this.nextCapacityCleanupAt) {
        this.removeExpired(now);
        this.nextCapacityCleanupAt = now + 1_000;
        if (this.entries.size >= this.maxEntries) {
          const earliestReset = Math.min(
            ...Array.from(this.entries.values(), (entry) => entry.resetAt),
          );
          this.capacityRetryAfterSeconds = this.retryAfterSeconds(earliestReset, now);
        }
      }
      if (this.entries.size >= this.maxEntries) {
        return this.capacityRetryAfterSeconds;
      }
    }

    this.entries.set(key, { count: 1, resetAt: now + windowMs });
    return undefined;
  }

  private removeExpired(now: number): void {
    for (const [key, entry] of this.entries) {
      if (entry.resetAt <= now) this.entries.delete(key);
    }
  }

  private retryAfterSeconds(resetAt: number, now: number): number {
    return Math.max(1, Math.ceil((resetAt - now) / 1000));
  }
}
