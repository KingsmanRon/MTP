import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/**
 * POST /api/portal/test-verify
 * Server-side proxy for the playground. The caller's API key is read from the
 * encrypted session cookie so it never leaves the server.
 */
export async function POST(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const body = await request.json();

  const upstream = await fetch(`${BACKEND_URL}/admin/test-verify`, {
    method: "POST",
    headers: {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    cache: "no-store",
  });

  const data = await upstream.json().catch(() => ({}));
  return NextResponse.json(data, { status: upstream.status });
}
