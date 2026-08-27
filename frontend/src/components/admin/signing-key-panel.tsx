"use client";

import { useState } from "react";
import { AlertTriangle, Check, Copy, KeyRound, RotateCw, ShieldAlert } from "lucide-react";
import type { MappedAgent } from "@/lib/admin/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { copyToClipboard, formatDateTime } from "@/lib/utils";

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}

// Generates an Ed25519 keypair in the browser via WebCrypto. The 32-byte seed
// is the tail of the PKCS#8 export (fixed 16-byte prefix), which is exactly the
// format the action's private-key-b64 expects. The seed never leaves the
// browser; only the public key is sent to the server.
async function generateEd25519(): Promise<{ publicKeyB64: string; seedB64: string }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
  const seed = pkcs8.slice(pkcs8.length - 32);
  return { publicKeyB64: toBase64(rawPub), seedB64: toBase64(seed) };
}

type Phase =
  | { kind: "idle" }
  | { kind: "working" }
  | { kind: "rotated"; seedB64: string; version: number; fingerprint: string }
  | { kind: "error"; message: string };

export function SigningKeyPanel({ agent }: { agent: MappedAgent }) {
  const [phase, setPhase] = useState<Phase>({ kind: "idle" });
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [copied, setCopied] = useState(false);

  // Reflect the latest known key locally so the display updates after rotation
  // without a full page refetch.
  const fingerprint =
    phase.kind === "rotated" ? phase.fingerprint : agent.public_key_fingerprint;
  const version = phase.kind === "rotated" ? phase.version : agent.key_version;

  const rotate = async () => {
    setConfirming(false);
    setPhase({ kind: "working" });
    try {
      if (typeof crypto === "undefined" || !crypto.subtle) {
        throw new Error("This browser cannot generate keys; rotate via the CLI runbook.");
      }
      let keys: { publicKeyB64: string; seedB64: string };
      try {
        keys = await generateEd25519();
      } catch {
        throw new Error(
          "This browser does not support Ed25519 key generation; rotate via the CLI runbook.",
        );
      }
      const res = await fetch(`/api/admin/agents/${agent.id}/rotate-key`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ public_key: keys.publicKeyB64, reason: reason || undefined }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        throw new Error(body?.detail || body?.error || `Rotation failed (${res.status})`);
      }
      setPhase({
        kind: "rotated",
        seedB64: keys.seedB64,
        version: body.key_version,
        fingerprint: body.public_key_fingerprint,
      });
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : "Rotation failed" });
    }
  };

  const copySeed = async (value: string) => {
    if (await copyToClipboard(value)) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  };

  return (
    <div className="rounded-lg border border-tileLine bg-card p-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <KeyRound className="mt-0.5 h-4 w-4 text-brandInk" />
          <div>
            <h2 className="text-sm font-semibold text-foreground">Signing key</h2>
            <p className="mt-1 max-w-xl text-xs leading-5 text-muted-foreground">
              Rotate if the <span className="font-mono">INNTRIS_PRIVATE_KEY_B64</span> secret may
              have leaked. The new keypair is generated in your browser; the old key stops
              verifying immediately, and trust score, policy, and audit history are preserved.
            </p>
          </div>
        </div>
        <Badge variant="secondary" className="shrink-0 font-mono text-[10px]">
          key v{version ?? 1}
        </Badge>
      </div>

      <div className="mt-4 grid gap-2 text-xs">
        <Row label="Fingerprint">
          <span className="font-mono text-muted-foreground">
            {fingerprint ? `${fingerprint.slice(0, 16)}…` : "—"}
          </span>
        </Row>
        {agent.key_rotated_at && phase.kind !== "rotated" && (
          <Row label="Last rotated">
            <span className="text-muted-foreground">{formatDateTime(agent.key_rotated_at)}</span>
          </Row>
        )}
      </div>

      {phase.kind === "rotated" ? (
        <div className="mt-4 space-y-3">
          <div className="flex items-start gap-2 rounded-md border border-success-line bg-success-surface p-3 text-xs text-success-ink">
            <Check className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            Rotated to key v{phase.version}. The previous key no longer verifies.
          </div>
          <div className="rounded-md border border-warning-line bg-warning-surface p-3">
            <p className="text-xs font-medium text-warning-ink">
              New private key — shown once. Update the secret now.
            </p>
            <p className="mt-1 text-[11px] text-muted-foreground">
              Set <span className="font-mono">INNTRIS_PRIVATE_KEY_B64</span> in the repo&apos;s
              GitHub Secrets to this value. It is not stored and cannot be shown again.
            </p>
            <div className="mt-2 flex items-center gap-2">
              <code className="flex-1 overflow-x-auto rounded border border-tileLine bg-background p-2 font-mono text-[11px] text-brandInk">
                {phase.seedB64}
              </code>
              <Button
                type="button"
                size="sm"
                variant="outline"
                onClick={() => copySeed(phase.seedB64)}
                className="shrink-0 border-tileLine bg-tile text-muted-foreground"
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          {phase.kind === "error" && (
            <div className="flex items-start gap-2 rounded-md border border-destructive-line bg-destructive-surface p-2.5 text-xs text-destructive-ink">
              <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {phase.message}
            </div>
          )}
          {confirming ? (
            <div className="rounded-md border border-warning-line bg-warning-surface p-3">
              <div className="flex items-start gap-2 text-xs text-warning-ink">
                <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                This immediately invalidates the current key. Any workflow still using the old
                secret will fail until you update it.
              </div>
              <input
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                placeholder="Reason (optional, recorded for audit)"
                className="mt-3 w-full rounded-md border border-tileLine bg-tile p-2 text-xs text-brandInk placeholder:text-muted-foreground"
              />
              <div className="mt-3 flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  onClick={rotate}
                  className="bg-destructive text-white hover:bg-destructive/90"
                >
                  Generate &amp; rotate
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setConfirming(false)}
                  className="border-tileLine bg-tile text-muted-foreground"
                >
                  Cancel
                </Button>
              </div>
            </div>
          ) : (
            <Button
              type="button"
              size="sm"
              variant="outline"
              disabled={phase.kind === "working"}
              onClick={() => setConfirming(true)}
              className="border-tileLine bg-tile text-muted-foreground"
            >
              <RotateCw className="mr-2 h-3.5 w-3.5" />
              {phase.kind === "working" ? "Rotating…" : "Rotate signing key"}
            </Button>
          )}
        </div>
      )}
    </div>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-tileLine bg-background px-3 py-2">
      <span className="text-muted-foreground">{label}</span>
      {children}
    </div>
  );
}
