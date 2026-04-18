import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function POST(
  _request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const result = await adminFetch(`/admin/alerts/${id}/acknowledge`, apiKey, {
    method: "POST",
  });
  return NextResponse.json(result.data, { status: result.status });
}
