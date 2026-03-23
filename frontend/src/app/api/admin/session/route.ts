import { NextRequest, NextResponse } from "next/server";
import { createSession, getSessionApiKey, destroySession } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

/**
 * POST /api/admin/session
 * Validate the API key against the backend, then create a secure session.
 */
export async function POST(request: NextRequest) {
  try {
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
