import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ log_id: string }> }
) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { log_id } = await params;
  const result = await adminFetch(`/admin/audit/${log_id}/proof`, apiKey);
  // A 501 from backend is valid — pass through, do not remap
  return NextResponse.json(result.data, { status: result.status });
}
