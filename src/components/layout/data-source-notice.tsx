import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Database } from "lucide-react";
import { getStorageStats } from "@/lib/aie/server";
import type { StorageStats } from "@/lib/aie/types";
import { explainMongoError } from "@/lib/mongodb/connection-errors";
import { cn } from "@/lib/cn";

/**
 * Says where the library comes from when it is not the analyst's MongoDB: the built-in local
 * database (MONGODB_URI not set) or a MongoDB that cannot be reached. Shares the ["nav-counts"]
 * query with the app shell, so it costs no extra request.
 */
export function DataSourceNotice({ className }: { className?: string }) {
  const { data } = useQuery({ queryKey: ["nav-counts"], queryFn: () => getStorageStats(), staleTime: 5 * 60_000 });
  const notice = describe(data);
  if (!notice) return null;
  const color = notice.tone === "danger" ? "var(--color-danger)" : "var(--color-info)";
  const Icon = notice.tone === "danger" ? AlertTriangle : Database;
  return (
    <div
      role={notice.tone === "danger" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-xl border px-4 py-3 text-sm", className)}
      style={{ borderColor: `color-mix(in oklab, ${color} 30%, transparent)`, backgroundColor: `color-mix(in oklab, ${color} 7%, transparent)` }}
    >
      <Icon className="mt-0.5 size-4 shrink-0" style={{ color }} strokeWidth={1.75} />
      <div className="min-w-0 space-y-1">
        <p className="font-medium text-fg">{notice.title}</p>
        <p className="text-muted">{notice.body}</p>
        {notice.detail && <p className="break-words font-mono text-xs text-subtle">{notice.detail}</p>}
      </div>
    </div>
  );
}

function describe(stats: StorageStats | undefined): { tone: "info" | "danger"; title: string; body: string; detail?: string } | null {
  if (!stats) return null;
  if (stats.engine === "local") {
    // Production with no shared database: nothing is being saved or shared — a hard error, not a hint.
    if (stats.required) {
      return {
        tone: "danger",
        title: "No shared database is configured — threat intelligence is not being saved",
        body: "AIE needs one shared MongoDB for its whole library, sources and accounts, but MONGODB_URI is not set on this deployment, so every visitor is on a private, empty store and nothing is saved or shared. Set MONGODB_URI once in the server environment (e.g. Vercel → Settings → Environment Variables) and redeploy.",
      };
    }
    return {
      tone: "info",
      title: "This is the built-in local database, not your MongoDB library",
      body: "MONGODB_URI is not set on the server, so reports stored in MongoDB are not loaded. Add MONGODB_URI to the server environment (or a .env file next to package.json) and restart the app.",
    };
  }
  if (stats.engine === "mongodb" && stats.error) {
    return { tone: "danger", title: "MongoDB is not reachable, so the library cannot load", body: explainMongoError(stats.error), detail: stats.error };
  }
  return null;
}
