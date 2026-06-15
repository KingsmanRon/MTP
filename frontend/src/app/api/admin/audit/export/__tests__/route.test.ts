/**
 * @jest-environment node
 */

import { getSessionApiKey } from "@/lib/admin/session";
import type { NextRequest } from "next/server";
import { GET } from "../route";

jest.mock("@/lib/admin/session", () => ({
  getSessionApiKey: jest.fn(),
}));

const mockedGetSessionApiKey =
  getSessionApiKey as jest.MockedFunction<typeof getSessionApiKey>;

function request(query: string) {
  return {
    nextUrl: { searchParams: new URLSearchParams(query) },
  } as NextRequest;
}

describe("audit export proxy", () => {
  beforeEach(() => {
    jest.restoreAllMocks();
    mockedGetSessionApiKey.mockReset();
  });

  it("rejects requests without an admin session", async () => {
    mockedGetSessionApiKey.mockResolvedValue(null);
    const fetchSpy = jest.spyOn(global, "fetch");

    const response = await GET(
      request("format=csv"),
    );

    expect(response.status).toBe(401);
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("forwards filters and preserves download headers", async () => {
    mockedGetSessionApiKey.mockResolvedValue("inntris_test_key");
    const fetchSpy = jest.spyOn(global, "fetch").mockResolvedValue(
      new Response("id,verdict\n1,approved\n", {
        status: 200,
        headers: {
          "content-type": "text/csv",
          "content-disposition": 'attachment; filename="audit_logs.csv"',
        },
      }),
    );

    const response = await GET(
      request("format=csv&agent_id=agent-1&ignored=yes"),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/csv");
    expect(response.headers.get("content-disposition")).toContain("audit_logs.csv");
    expect(fetchSpy).toHaveBeenCalledWith(
      "http://localhost:8000/admin/audit/export?format=csv&agent_id=agent-1",
      {
        headers: { "X-API-Key": "inntris_test_key" },
        cache: "no-store",
      },
    );
  });

  it("rejects unsupported formats before calling the backend", async () => {
    mockedGetSessionApiKey.mockResolvedValue("inntris_test_key");
    const fetchSpy = jest.spyOn(global, "fetch");

    const response = await GET(
      request("format=pdf"),
    );

    expect(response.status).toBe(400);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
