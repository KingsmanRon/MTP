"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  ArrowLeft,
  CheckCircle2,
  ShieldCheck,
  ExternalLink,
  Clock,
  Fingerprint,
  FileJson,
  Blocks,
  Loader2,
  AlertTriangle
} from "lucide-react";
import { useAuditLog, useMerkleProof } from "@/lib/hooks";
import { formatDateTime } from "@/lib/utils";

const BLOCK_EXPLORER_URL = "https://basescan.org";

export default function VerificationPage() {
  const params = useParams();
  const logId = params.logId as string;

  const { data: log, isLoading: logLoading, error: logError } = useAuditLog(logId);
  const { data: proof, isLoading: proofLoading } = useMerkleProof(logId, !!log?.merkle_root_id);

  const loading = logLoading || (log?.merkle_root_id && proofLoading);
  const error = logError ? "Failed to load audit record. It may not exist or access is denied." : null;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <Loader2 className="h-10 w-10 animate-spin text-primary" />
        <p className="text-muted-foreground">Verifying cryptographic proofs...</p>
      </div>
    );
  }

  if (error || !log) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4 text-center">
        <div className="bg-red-100 p-4 rounded-full">
          <AlertTriangle className="h-8 w-8 text-red-600" />
        </div>
        <h2 className="text-2xl font-bold">Verification Failed</h2>
        <p className="text-muted-foreground max-w-md">{error}</p>
        <Link href="/audit">
          <Button variant="outline" className="mt-4">
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Explorer
          </Button>
        </Link>
      </div>
    );
  }

  const isAnchored = !!proof;

  return (
    <div className="max-w-5xl mx-auto space-y-8 pb-10">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Link href="/audit">
            <Button variant="ghost" size="icon">
              <ArrowLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              Forensic Verification
              {isAnchored && (
                <Badge variant="outline" className="bg-green-500/10 text-green-600 border-green-500/20">
                  <ShieldCheck className="w-3 h-3 mr-1" />
                  Cryptographically Secured
                </Badge>
              )}
            </h1>
            <p className="text-muted-foreground text-sm">
              Log ID: <span className="font-mono">{log.id}</span>
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          {isAnchored && (
            /* FIXED: Wrap Button in anchor tag instead of using asChild */
            <a 
              href={`${BLOCK_EXPLORER_URL}/tx/${proof.tx_hash}`} 
              target="_blank" 
              rel="noopener noreferrer"
            >
              <Button variant="outline">
                <Blocks className="mr-2 h-4 w-4" />
                View on BaseScan
              </Button>
            </a>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        
        {/* LEFT COLUMN: The Blockchain Proof */}
        <div className="md:col-span-1 space-y-6">
          <Card className={`border-t-4 ${isAnchored ? "border-t-green-500" : "border-t-yellow-500"}`}>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ShieldCheck className="h-5 w-5" />
                Chain of Custody
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-6">
              
              <div className="flex flex-col items-center justify-center p-6 bg-muted/30 rounded-lg border border-dashed">
                {isAnchored ? (
                  <>
                    <div className="bg-green-100 p-3 rounded-full mb-3">
                      <CheckCircle2 className="h-8 w-8 text-green-600" />
                    </div>
                    <h3 className="font-bold text-green-700">Anchored on Base L2</h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      {formatDateTime(proof.anchored_at)}
                    </p>
                  </>
                ) : (
                  <>
                    <div className="bg-yellow-100 p-3 rounded-full mb-3">
                      <Clock className="h-8 w-8 text-yellow-600" />
                    </div>
                    <h3 className="font-bold text-yellow-700">Pending Anchor</h3>
                    <p className="text-xs text-muted-foreground mt-1">
                      Scheduled for next batch
                    </p>
                  </>
                )}
              </div>

              {isAnchored && (
                <div className="space-y-4 text-sm">
                  <div>
                    <span className="text-muted-foreground text-xs uppercase tracking-wider">Transaction Hash</span>
                    <div className="flex items-center gap-2 mt-1">
                      <code className="bg-muted p-1 rounded text-xs truncate w-full block">
                        {proof.tx_hash}
                      </code>
                      <a href={`${BLOCK_EXPLORER_URL}/tx/${proof.tx_hash}`} target="_blank" rel="noopener noreferrer">
                        <ExternalLink className="h-3 w-3 text-primary cursor-pointer hover:underline" />
                      </a>
                    </div>
                  </div>

                  <div>
                    <span className="text-muted-foreground text-xs uppercase tracking-wider">Merkle Root</span>
                    <div className="mt-1">
                      <code className="bg-muted p-1 rounded text-xs break-all">
                        {proof.merkle_root}
                      </code>
                    </div>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
               <CardTitle className="text-lg">Trust Context</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Score</span>
                  <Badge variant={log.trust_score_at_time > 70 ? "default" : "destructive"}>
                    {log.trust_score_at_time}/100
                  </Badge>
                </div>
                <div className="flex justify-between items-center">
                  <span className="text-sm text-muted-foreground">Verdict</span>
                  <Badge variant="outline">{log.verdict}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* RIGHT COLUMN: The Log Details */}
        <div className="md:col-span-2 space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <FileJson className="h-5 w-5" />
                Event Payload
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="bg-slate-950 text-slate-50 p-4 rounded-lg overflow-x-auto text-sm font-mono leading-relaxed">
                {JSON.stringify(log.payload, null, 2)}
              </pre>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Fingerprint className="h-5 w-5" />
                Technical Metadata
              </CardTitle>
            </CardHeader>
            <CardContent>
              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-6 text-sm">
                <div>
                  <dt className="text-muted-foreground text-xs uppercase tracking-wider">Action Hash</dt>
                  <dd className="font-mono mt-1 break-all bg-muted p-2 rounded">
                    {log.action_hash}
                  </dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs uppercase tracking-wider">Timestamp</dt>
                  <dd className="mt-1 font-medium">{formatDateTime(log.timestamp)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground text-xs uppercase tracking-wider">Signature</dt>
                  <dd className="mt-1">
                    {log.signature_valid ? (
                      <span className="text-green-600 font-medium flex items-center gap-1">
                        <CheckCircle2 className="h-3 w-3" /> Valid Ed25519
                      </span>
                    ) : (
                      <span className="text-red-600 font-medium">Invalid</span>
                    )}
                  </dd>
                </div>
              </dl>
            </CardContent>
          </Card>
        </div>

      </div>
    </div>
  );
}
