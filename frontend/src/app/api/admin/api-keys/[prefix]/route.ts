import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function DELETE(
  _request: NextRequest,
  { params }: { params: Promise<{ prefix: string }> }
) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const { prefix } = await params;
  const result = await adminFetch(
    `/admin/api-keys/${encodeURIComponent(prefix)}`,
    apiKey,
    { method: "DELETE" }
  );
  return NextResponse.json(result.data, { status: result.status });
}
