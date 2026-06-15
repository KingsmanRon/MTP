import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { getSessionApiKey } from "@/lib/admin/session";

const BACKEND_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function GET(request: NextRequest) {
  const apiKey = await getSessionApiKey();
  if (!apiKey) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const incoming = request.nextUrl.searchParams;
  const format = incoming.get("format") || "csv";
  if (format !== "csv" && format !== "json") {
    return NextResponse.json(
      { error: "format must be csv or json" },
      { status: 400 },
    );
  }

  const params = new URLSearchParams({ format });
  for (const key of ["start", "end", "agent_id"]) {
    const value = incoming.get(key);
    if (value) params.set(key, value);
  }

  const upstream = await fetch(
    `${BACKEND_URL}/admin/audit/export?${params.toString()}`,
    {
      headers: { "X-API-Key": apiKey },
      cache: "no-store",
    },
  );
  const body = await upstream.arrayBuffer();
  const disposition = upstream.headers.get("content-disposition");

  return new NextResponse(body, {
    status: upstream.status,
    headers: {
      "Content-Type":
        upstream.headers.get("content-type") || "application/octet-stream",
      ...(disposition ? { "Content-Disposition": disposition } : {}),
    },
  });
}
