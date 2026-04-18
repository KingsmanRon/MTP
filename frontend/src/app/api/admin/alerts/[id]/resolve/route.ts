import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const { id } = await params;
  const body = await request.json().catch(() => ({}));
  const resolution = typeof body.resolution === "string" ? body.resolution : "";

  if (!resolution) {
    return NextResponse.json(
      { error: "resolution is required" },
      { status: 400 }
    );
  }

  const result = await adminFetch(`/admin/alerts/${id}/resolve`, apiKey, {
    method: "POST",
    body: { resolution },
  });
  return NextResponse.json(result.data, { status: result.status });
}
