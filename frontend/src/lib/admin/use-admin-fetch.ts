"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";

interface FetchState<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
  refetch: () => void;
}

/**
 * Fetch data from an admin proxy endpoint.
 * Redirects to login on 401.
 * Pass refetchInterval (ms) to poll — background polls never flash the loading
 * skeleton because loading stays false once the first response arrives.
 */
export function useAdminFetch<T>(
  url: string | null,
  opts?: { transform?: (raw: unknown) => T; refetchInterval?: number }
): FetchState<T> {
  const router = useRouter();
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);
  const hasData = useRef(false);

  const refetch = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (!url) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    // Only show the skeleton on the very first fetch; subsequent polls are silent.
    if (!hasData.current) setLoading(true);
    setError(null);

    (async () => {
      try {
        const res = await fetch(url);
        if (cancelled) return;

        if (res.status === 401) {
          router.replace("/admin/login");
          return;
        }

        if (!res.ok) {
          const body = await res.json().catch(() => ({}));
          const msg =
            typeof body.error === "string"
              ? body.error
              : typeof body.message === "string"
                ? body.message
                : `Error ${res.status}`;
          setError(msg);
          setLoading(false);
          return;
        }

        const raw = await res.json();
        if (cancelled) return;
        hasData.current = true;
        setData(opts?.transform ? opts.transform(raw) : (raw as T));
      } catch {
        if (!cancelled) setError("Network error");
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [url, tick, router]);

  useEffect(() => {
    if (!opts?.refetchInterval) return;
    const id = setInterval(refetch, opts.refetchInterval);
    return () => clearInterval(id);
  }, [opts?.refetchInterval, refetch]);

  return { data, error, loading, refetch };
}
