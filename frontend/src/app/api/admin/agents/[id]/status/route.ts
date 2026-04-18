import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

/**
 * PATCH /api/admin/agents/:id/status
 * Body: { status: "active" | "suspended" | ... }
 * Proxies to backend PATCH /admin/agents/:id/status?new_status=...
 */
export async function PATCH(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const body = await request.json().catch(() => ({}));
  const newStatus = typeof body.status === "string" ? body.status : "";

  if (!newStatus) {
    return NextResponse.json(
      { error: "status is required" },
      { status: 400 }
    );
  }

  const result = await adminFetch(
    `/admin/agents/${id}/status`,
    apiKey,
    { method: "PATCH", params: { new_status: newStatus } }
  );
  return NextResponse.json(result.data, { status: result.status });
}
