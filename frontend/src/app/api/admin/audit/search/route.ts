import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

/**
 * GET /api/admin/audit/search
 * Forwards documented query params to GET /admin/audit/search.
 * Supported params: agent_id, action_type, verdict, start, end, limit, offset.
 */
export async function GET(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sp = request.nextUrl.searchParams;

  // Forward only documented query params
  const params: Record<string, string | undefined> = {
    agent_id: sp.get("agent_id") ?? undefined,
    action_type: sp.get("action_type") ?? undefined,
    verdict: sp.get("verdict") ?? undefined,
    start: sp.get("start") ?? undefined,
    end: sp.get("end") ?? undefined,
    limit: sp.get("limit") ?? undefined,
    offset: sp.get("offset") ?? undefined,
  };

  const result = await adminFetch("/admin/audit/search", apiKey, { params });
  return NextResponse.json(result.data, { status: result.status });
}
