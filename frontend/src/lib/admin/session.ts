import { cookies } from "next/headers";
import * as crypto from "crypto";

// ---------------------------------------------------------------------------
// Server-side session management for admin UI.
// The admin API key is encrypted (AES-256-GCM) and stored in an HTTP-only
// cookie. The browser never sees the raw key.
// ---------------------------------------------------------------------------

const COOKIE_NAME = "inntris_admin_session";
const COOKIE_MAX_AGE = 60 * 60 * 8; // 8 hours

// The encryption secret must be at least 32 bytes. In production this should
// come from an environment variable. We derive a stable 32-byte key from
// whatever is provided (or a fallback for local dev).
function getEncryptionKey(): Buffer {
  const secret =
    process.env.ADMIN_SESSION_SECRET || "inntris-dev-session-secret-change-me";
  return crypto.createHash("sha256").update(secret).digest();
}

function encrypt(plaintext: string): string {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag();
  // iv (12) + authTag (16) + ciphertext
  const combined = Buffer.concat([iv, authTag, encrypted]);
  return combined.toString("base64url");
}

function decrypt(token: string): string | null {
  try {
    const key = getEncryptionKey();
    const combined = Buffer.from(token, "base64url");
    const iv = combined.subarray(0, 12);
    const authTag = combined.subarray(12, 28);
    const ciphertext = combined.subarray(28);
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);
    return decrypted.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Create a session cookie containing the encrypted admin API key. */
export async function createSession(apiKey: string): Promise<void> {
  const token = encrypt(apiKey);
  const jar = await cookies();
  jar.set(COOKIE_NAME, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: COOKIE_MAX_AGE,
  });
}

/** Read the admin API key from the session cookie. Returns null if absent or tampered. */
export async function getSessionApiKey(): Promise<string | null> {
  const jar = await cookies();
  const cookie = jar.get(COOKIE_NAME);
  if (!cookie?.value) return null;
  return decrypt(cookie.value);
}

/** Destroy the session cookie. */
export async function destroySession(): Promise<void> {
  const jar = await cookies();
  jar.set(COOKIE_NAME, "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
}

/** Check if a valid session exists (without returning the key). */
export async function hasSession(): Promise<boolean> {
  const key = await getSessionApiKey();
  return key !== null && key.length > 0;
}
