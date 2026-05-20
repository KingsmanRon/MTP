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

    // Fail closed: if Redis is not configured or is unreachable we cannot
    // enforce the login rate limit. In that state we refuse new sign-ins
    // rather than silently skipping the check — an attacker who can reach
    // /api/admin/session could otherwise brute-force keys unbounded. Set
    // INNTRIS_DISABLE_LOGIN_RATE_LIMIT=1 only in dev environments where
    // brute-force is not a concern.
    const rateLimitDisabled =
      process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT === "1";

    const redis = getRedis();
    if (!redis) {
      if (!rateLimitDisabled) {
        console.error(
          "Login rejected: Redis unavailable, cannot enforce rate limit (fail closed)"
        );
        return NextResponse.json(
          {
            error: "Authentication service temporarily unavailable",
            hint: "Operator: REDIS_URL is not configured or unreachable. Set INNTRIS_DISABLE_LOGIN_RATE_LIMIT=1 to bypass (dev only).",
          },
          { status: 503 }
        );
      }
      console.warn(
        "Redis unavailable and INNTRIS_DISABLE_LOGIN_RATE_LIMIT=1 — login rate limit skipped"
      );
    } else {
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
      } catch (err) {
        if (!rateLimitDisabled) {
          console.error(
            "Login rejected: Redis command failed, cannot enforce rate limit (fail closed)",
            err
          );
          return NextResponse.json(
            { error: "Authentication service temporarily unavailable" },
            { status: 503 }
          );
        }
        console.warn(
          "Redis command failed and INNTRIS_DISABLE_LOGIN_RATE_LIMIT=1 — login rate limit skipped"
        );
      }
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
    try {
      await createSession(apiKey);
    } catch (sessionErr) {
      // The only realistic failure here is a misconfigured encryption secret.
      // Surface the actual cause in logs and the response so operators can
      // diagnose without reading source.
      const detail = sessionErr instanceof Error ? sessionErr.message : "Unknown";
      console.error("Session creation failed:", detail);
      if (detail.includes("ADMIN_SESSION_SECRET")) {
        return NextResponse.json(
          {
            error: "Server misconfiguration: ADMIN_SESSION_SECRET is missing or too short",
            hint: "Set ADMIN_SESSION_SECRET to a base64-encoded value of at least 32 bytes and redeploy.",
          },
          { status: 500 }
        );
      }
      return NextResponse.json(
        { error: "Session creation failed", detail },
        { status: 500 }
      );
    }

    return NextResponse.json({ ok: true });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    console.error("Admin login handler error:", message);
    if (message.includes("fetch") || message.includes("ECONNREFUSED")) {
      return NextResponse.json(
        { error: "Cannot connect to backend API", detail: message },
        { status: 502 }
      );
    }
    return NextResponse.json(
      { error: "Internal error", detail: message },
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
