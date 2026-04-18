import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

/**
 * GET /api/admin/alerts
 * Forwards documented query params: status, severity, limit, offset.
 */
export async function GET(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sp = request.nextUrl.searchParams;
  const params: Record<string, string | undefined> = {
    status: sp.get("status") ?? undefined,
    severity: sp.get("severity") ?? undefined,
    limit: sp.get("limit") ?? undefined,
    offset: sp.get("offset") ?? undefined,
  };

  const result = await adminFetch("/admin/alerts", apiKey, { params });
  return NextResponse.json(result.data, { status: result.status });
}
