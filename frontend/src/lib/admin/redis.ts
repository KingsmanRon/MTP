import Redis from "ioredis";

let client: Redis | null = null;

/**
 * Get a shared Redis client. Returns null if REDIS_URL is not configured
 * or if connection fails.
 */
export function getRedis(): Redis | null {
  if (client) return client;

  const url = process.env.REDIS_URL;
  if (!url) return null;

  try {
    client = new Redis(url, {
      maxRetriesPerRequest: 1,
      connectTimeout: 2000,
      lazyConnect: true,
    });
    client.on("error", () => {
      // Swallow connection errors — callers check for null
    });
    return client;
  } catch {
    return null;
  }
}
