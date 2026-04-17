/**
 * @jest-environment node
 *
 * Phase 0.2 — verify that /api/admin/session fails closed when Redis is not
 * available, and that the existing happy path still works when it is.
 */

import { NextRequest } from "next/server";

// ---------------------------------------------------------------------------
// Module mocks
// ---------------------------------------------------------------------------

jest.mock("@/lib/admin/redis", () => ({
  getRedis: jest.fn(),
}));

jest.mock("@/lib/admin/api-client", () => ({
  adminFetch: jest.fn(),
}));

jest.mock("@/lib/admin/session", () => ({
  createSession: jest.fn(),
  getSessionApiKey: jest.fn(),
  destroySession: jest.fn(),
}));

import { getRedis } from "@/lib/admin/redis";
import { adminFetch } from "@/lib/admin/api-client";
import { createSession } from "@/lib/admin/session";
import { POST } from "@/app/api/admin/session/route";

const mockedGetRedis = getRedis as jest.MockedFunction<typeof getRedis>;
const mockedAdminFetch = adminFetch as jest.MockedFunction<typeof adminFetch>;
const mockedCreateSession = createSession as jest.MockedFunction<typeof createSession>;

function buildRequest(body: unknown): NextRequest {
  return new NextRequest("http://localhost/api/admin/session", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-forwarded-for": "10.0.0.1",
    },
    body: JSON.stringify(body),
  });
}

describe("POST /api/admin/session — rate-limit fail-closed", () => {
  const originalDisable = process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT;
  let errorSpy: jest.SpyInstance;
  let warnSpy: jest.SpyInstance;

  beforeEach(() => {
    jest.clearAllMocks();
    delete process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT;
    // Route handler intentionally logs fail-closed rejections. Silence those
    // messages in the test output — we assert on response status, not logs.
    errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});
    warnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    errorSpy.mockRestore();
    warnSpy.mockRestore();
  });

  afterAll(() => {
    if (originalDisable === undefined) {
      delete process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT;
    } else {
      process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT = originalDisable;
    }
  });

  it("returns 503 when Redis is not configured", async () => {
    mockedGetRedis.mockReturnValue(null);

    const res = await POST(buildRequest({ api_key: "ink_test" }));

    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.error).toMatch(/temporarily unavailable/i);
    expect(mockedAdminFetch).not.toHaveBeenCalled();
    expect(mockedCreateSession).not.toHaveBeenCalled();
  });

  it("returns 503 when Redis commands throw", async () => {
    const fakeRedis = {
      get: jest.fn().mockRejectedValue(new Error("ECONNREFUSED")),
      incr: jest.fn(),
      expire: jest.fn(),
    };
    // The production code only uses these three methods.
    mockedGetRedis.mockReturnValue(fakeRedis as unknown as ReturnType<typeof getRedis>);

    const res = await POST(buildRequest({ api_key: "ink_test" }));

    expect(res.status).toBe(503);
    expect(mockedAdminFetch).not.toHaveBeenCalled();
    expect(mockedCreateSession).not.toHaveBeenCalled();
  });

  it("bypasses the fail-closed check only when the kill-switch env var is set", async () => {
    process.env.INNTRIS_DISABLE_LOGIN_RATE_LIMIT = "1";
    mockedGetRedis.mockReturnValue(null);
    mockedAdminFetch.mockResolvedValue({
      ok: true,
      status: 200,
      data: { id: "org_1", name: "Test Org" },
    });

    const res = await POST(buildRequest({ api_key: "ink_test" }));

    expect(res.status).toBe(200);
    expect(mockedAdminFetch).toHaveBeenCalledWith("/admin/organization", "ink_test");
    expect(mockedCreateSession).toHaveBeenCalledWith("ink_test");
  });

  it("enforces the rate limit when Redis is healthy", async () => {
    const fakeRedis = {
      get: jest.fn().mockResolvedValue("5"),
      incr: jest.fn(),
      expire: jest.fn(),
    };
    mockedGetRedis.mockReturnValue(fakeRedis as unknown as ReturnType<typeof getRedis>);

    const res = await POST(buildRequest({ api_key: "ink_test" }));

    expect(res.status).toBe(429);
    expect(mockedAdminFetch).not.toHaveBeenCalled();
  });

  it("allows sign-in under the rate-limit threshold", async () => {
    const fakeRedis = {
      get: jest.fn().mockResolvedValue("1"),
      incr: jest.fn().mockResolvedValue(2),
      expire: jest.fn().mockResolvedValue(1),
    };
    mockedGetRedis.mockReturnValue(fakeRedis as unknown as ReturnType<typeof getRedis>);
    mockedAdminFetch.mockResolvedValue({
      ok: true,
      status: 200,
      data: { id: "org_1", name: "Test Org" },
    });

    const res = await POST(buildRequest({ api_key: "ink_test" }));

    expect(res.status).toBe(200);
    expect(mockedCreateSession).toHaveBeenCalledWith("ink_test");
  });
});
