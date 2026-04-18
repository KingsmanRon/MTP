import { NextRequest, NextResponse } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";
import { adminFetch } from "@/lib/admin/api-client";

export async function GET(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const sp = request.nextUrl.searchParams;
  const params: Record<string, string | undefined> = {
    start: sp.get("start") ?? undefined,
    end: sp.get("end") ?? undefined,
  };

  const result = await adminFetch("/admin/usage", apiKey, { params });
  return NextResponse.json(result.data, { status: result.status });
}
