import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function GET() {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const result = await adminFetch("/admin/organization", apiKey);
  return NextResponse.json(result.data, { status: result.status });
}

export async function PATCH(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }
  const body = await request.json().catch(() => ({}));
  const result = await adminFetch("/admin/organization", apiKey, {
    method: "PATCH",
    body,
  });
  return NextResponse.json(result.data, { status: result.status });
}
