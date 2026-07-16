import { cookies } from "next/headers";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Server-side session management for admin UI.
// The admin API key is encrypted (AES-256-GCM) and stored in an HTTP-only
// cookie. The browser never sees the raw key.
// ---------------------------------------------------------------------------

const COOKIE_NAME = "inntris_admin_session";
const SESSION_TTL = 3600; // 1 hour sliding window
const MAX_SESSION_AGE = 7200; // 2 hours absolute ceiling
const GCM_IV_LENGTH = 12;
const GCM_AUTH_TAG_LENGTH = 16;

// ---------------------------------------------------------------------------
// Startup validation — ensure the encryption secret is strong enough.
// In production, ADMIN_SESSION_SECRET must be set to a base64-encoded value
// of at least 32 bytes. In development, a fallback is used.
// ---------------------------------------------------------------------------

function getEncryptionKey(): Buffer {
  const secret = process.env.ADMIN_SESSION_SECRET;
  if (process.env.NODE_ENV === "production") {
    if (!secret || Buffer.from(secret, "base64").length < 32) {
      throw new Error(
        "ADMIN_SESSION_SECRET must be at least 32 bytes. Generate with: openssl rand -base64 32"
      );
    }
  }
  const raw = secret || "inntris-dev-session-secret-change-me";
  return crypto.createHash("sha256").update(raw).digest();
}

// ---------------------------------------------------------------------------
// Session payload — includes createdAt for absolute ceiling enforcement.
// ---------------------------------------------------------------------------

interface SessionPayload {
  apiKey: string;
  createdAt: number; // ms since epoch
}

function encrypt(payload: SessionPayload): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(GCM_IV_LENGTH);
  const plaintext = JSON.stringify(payload);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, {
    authTagLength: GCM_AUTH_TAG_LENGTH,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  // iv (12) + authTag (16) + ciphertext
  const combined = Buffer.concat([iv, authTag, encrypted]);
  return combined.toString("base64url");
}

function decrypt(token: string): SessionPayload | null {
  try {
    const key = getEncryptionKey();
    const combined = Buffer.from(token, "base64url");
    if (combined.length <= GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH) return null;
    const iv = combined.subarray(0, GCM_IV_LENGTH);
    const authTag = combined.subarray(
      GCM_IV_LENGTH,
      GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH
    );
    const ciphertext = combined.subarray(GCM_IV_LENGTH + GCM_AUTH_TAG_LENGTH);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv, {
      authTagLength: GCM_AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    const parsed = JSON.parse(decrypted.toString("utf8"));
    if (
      typeof parsed === "object" &&
      parsed !== null &&
      typeof parsed.apiKey === "string" &&
      typeof parsed.createdAt === "number"
    ) {
      return parsed as SessionPayload;
    }
    return null;
  } catch {
    return null;
  }
}

function cookieOptions(maxAge: number) {
  return {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict" as const,
    path: "/",
    maxAge,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Create a session cookie containing the encrypted admin API key. */
export async function createSession(apiKey: string): Promise<void> {
  const payload: SessionPayload = {
    apiKey,
    createdAt: Date.now(),
  };
  const token = encrypt(payload);
  const jar = await cookies();
  jar.set(COOKIE_NAME, token, cookieOptions(SESSION_TTL));
}

/**
 * Read the admin API key from the session cookie.
 * Returns null if absent, tampered, or past the absolute ceiling.
 * Performs sliding-window TTL extension capped by MAX_SESSION_AGE.
 */
export async function getSessionApiKey(): Promise<string | null> {
  const jar = await cookies();
  const cookie = jar.get(COOKIE_NAME);
  if (!cookie?.value) return null;

  const payload = decrypt(cookie.value);
  if (!payload) return null;

  // Enforce absolute ceiling
  const ageSeconds = (Date.now() - payload.createdAt) / 1000;
  if (ageSeconds > MAX_SESSION_AGE) {
    // Session expired — clear the cookie
    jar.set(COOKIE_NAME, "", cookieOptions(0));
    return null;
  }

  // Sliding window extension — recalculate remaining headroom
  const remainingCeiling = MAX_SESSION_AGE - ageSeconds;
  const newTtl = Math.min(SESSION_TTL, Math.floor(remainingCeiling));
  if (newTtl > 0) {
    // Re-encrypt with same payload to extend sliding window
    const token = encrypt(payload);
    jar.set(COOKIE_NAME, token, cookieOptions(newTtl));
  }

  return payload.apiKey;
}

/** Destroy the session cookie. */
export async function destroySession(): Promise<void> {
  const jar = await cookies();
  jar.set(COOKIE_NAME, "", cookieOptions(0));
}

/** Check if a valid session exists (without returning the key). */
export async function hasSession(): Promise<boolean> {
  const key = await getSessionApiKey();
  return key !== null && key.length > 0;
}
