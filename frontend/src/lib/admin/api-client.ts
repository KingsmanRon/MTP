// =============================================================================
// Server-side admin API client.
// Used by Next.js route handlers to call the backend with X-API-Key.
// =============================================================================

const BACKEND_URL =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface AdminApiResponse<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

/**
 * Make an authenticated request to the backend admin API.
 * This runs server-side only — the apiKey is never exposed to the browser.
 */
export async function adminFetch<T = unknown>(
  path: string,
  apiKey: string,
  options: {
    method?: string;
    params?: Record<string, string | undefined>;
  } = {}
): Promise<AdminApiResponse<T>> {
  const { method = "GET", params } = options;

  let url = `${BACKEND_URL}${path}`;
  if (params) {
    const searchParams = new URLSearchParams();
    for (const [key, value] of Object.entries(params)) {
      if (value !== undefined && value !== "") {
        searchParams.set(key, value);
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
  }

  const response = await fetch(url, {
    method,
    headers: {
      "X-API-Key": apiKey,
      "Content-Type": "application/json",
    },
    cache: "no-store",
  });

  let data: T;
  try {
    data = await response.json();
  } catch {
    data = {} as T;
  }

  return {
    ok: response.ok,
    status: response.status,
    data,
  };
}
