import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function GET() {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const result = await adminFetch("/admin/agents", apiKey);
  return NextResponse.json(result.data, { status: result.status });
}

/**
 * POST /api/admin/agents
 * Register a new agent in the authenticated org.
 *
 * The backend requires ``org_id`` in the body and rejects mismatches against
 * the authenticated key's org. We fetch the org from /admin/organization so
 * the browser caller doesn't have to know it.
 */
export async function POST(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await request.json().catch(() => ({}));

  // Pull org_id server-side so we never trust the browser for it.
  const orgResult = await adminFetch<{ id?: string }>("/admin/organization", apiKey);
  if (!orgResult.ok || !orgResult.data?.id) {
    return NextResponse.json(
      { error: "Unable to resolve organization for this API key" },
      { status: orgResult.status || 500 }
    );
  }

  const payload = {
    org_id: orgResult.data.id,
    name: body.name,
    public_key: body.public_key,
    ...(body.daily_limit_usd !== undefined && { daily_limit_usd: body.daily_limit_usd }),
    ...(body.per_action_limit_usd !== undefined && { per_action_limit_usd: body.per_action_limit_usd }),
    ...(Array.isArray(body.allowed_actions) && { allowed_actions: body.allowed_actions }),
    ...(body.metadata && typeof body.metadata === "object" && { metadata: body.metadata }),
  };

  const result = await adminFetch("/admin/agents", apiKey, {
    method: "POST",
    body: payload,
  });
  return NextResponse.json(result.data, { status: result.status });
}
