import { NextRequest, NextResponse } from "next/server";
import { createSession, getSessionApiKey, destroySession } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";
import { getRedis } from "@/lib/admin/redis";

const LOGIN_RATE_LIMIT = 5;
const LOGIN_RATE_WINDOW = 900; // 15 minutes in seconds

/**
 * POST /api/admin/session
 * Validate the API key against the backend, then create a secure session.
 */
export async function POST(request: NextRequest) {
  try {
    // -----------------------------------------------------------------------
    // Rate limiting by IP
    // -----------------------------------------------------------------------
    const forwarded = request.headers.get("x-forwarded-for") ?? "";
    const ip = forwarded.split(",")[0].trim() || "unknown";
    const rateLimitKey = `ratelimit:admin:login:${ip}`;

    const redis = getRedis();
    if (redis) {
      try {
        const count = await redis.get(rateLimitKey);
        if (count !== null && parseInt(count, 10) >= LOGIN_RATE_LIMIT) {
          return NextResponse.json(
            { error: "Too many login attempts. Try again in 15 minutes." },
            { status: 429 }
          );
        }
        const result = await redis.incr(rateLimitKey);
        if (result === 1) {
          // First attempt in this window — set expiry. Do not reset on subsequent
          // increments so the window does not slide.
          await redis.expire(rateLimitKey, LOGIN_RATE_WINDOW);
        }
      } catch {
        // Redis command failed — continue without rate limiting
        console.warn("Redis unavailable — login rate limit skipped");
        // TODO: change to fail closed before production
      }
    } else {
      console.warn("Redis unavailable — login rate limit skipped");
      // TODO: change to fail closed before production
    }

    // -----------------------------------------------------------------------
    // Credential validation
    // -----------------------------------------------------------------------
    const body = await request.json();
    const apiKey = typeof body.api_key === "string" ? body.api_key.trim() : "";

    if (!apiKey) {
      return NextResponse.json(
        { error: "API key is required" },
        { status: 400 }
      );
    }

    // Validate the key by calling GET /admin/organization
    const result = await adminFetch("/admin/organization", apiKey);

    if (!result.ok) {
      const status = result.status;
      if (status === 401 || status === 403) {
        return NextResponse.json(
          { error: "Invalid API key", detail: result.data },
          { status: 401 }
        );
      }
      return NextResponse.json(
        { error: "Backend error", detail: result.data },
        { status: status }
      );
    }

    // Key is valid — create session
    await createSession(apiKey);

    return NextResponse.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    if (message.includes("fetch") || message.includes("ECONNREFUSED")) {
      return NextResponse.json(
        { error: "Cannot connect to backend API" },
        { status: 502 }
      );
    }
    return NextResponse.json(
      { error: "Internal error" },
      { status: 500 }
    );
  }
}

/**
 * GET /api/admin/session
 * Check if a valid session exists.
 */
export async function GET() {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ authenticated: false }, { status: 401 });
  }
  return NextResponse.json({ authenticated: true });
}

/**
 * DELETE /api/admin/session
 * Sign out — destroy the session cookie.
 */
export async function DELETE() {
  await destroySession();
  return NextResponse.json({ ok: true });
}
