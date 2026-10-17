import { useState, type FormEvent } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, Loader2 } from "lucide-react";
import { toast } from "sonner";
import { changePassword } from "@/lib/aie/server-accounts";
import { PASSWORD_MIN_LENGTH, passwordError } from "@/lib/aie/accounts/policy";
import { ACCOUNT_SESSION_KEY } from "./use-app-session";

const field =
  "h-10 w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 disabled:opacity-60";

/** Current password + new password (twice). Signs out the account's other sessions on success. */
export function ChangePasswordForm({ username, onDone }: { username: string; onDone: () => void }) {
  const queryClient = useQueryClient();
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    const problem = passwordError(next, username);
    if (!current) return setError("Enter your current password.");
    if (problem) return setError(problem);
    if (next !== confirm) return setError("The new passwords do not match.");
    setBusy(true);
    try {
      const res = await changePassword({ data: { currentPassword: current, newPassword: next } });
      await queryClient.invalidateQueries({ queryKey: ACCOUNT_SESSION_KEY });
      toast.success(res.revokedSessions > 0 ? `Password changed. ${res.revokedSessions} other session${res.revokedSessions === 1 ? " was" : "s were"} signed out.` : "Password changed.");
      onDone();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The password could not be changed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form className="space-y-3.5" onSubmit={onSubmit} noValidate>
      {/* Lets password managers file the change under the right account. */}
      <input type="text" name="username" autoComplete="username" value={username} readOnly hidden />
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-fg">Current password</span>
        <input type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} disabled={busy} className={field} />
      </label>
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-fg">New password</span>
        <input type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} disabled={busy} className={field} />
        <span className="block text-xs text-subtle">At least {PASSWORD_MIN_LENGTH} characters, not your username.</span>
      </label>
      <label className="block space-y-1.5">
        <span className="text-sm font-medium text-fg">Confirm new password</span>
        <input type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} disabled={busy} className={field} />
      </label>
      <div aria-live="polite">
        {error && (
          <p className="flex items-start gap-2 text-sm text-danger">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" />
            <span>{error}</span>
          </p>
        )}
      </div>
      <div className="flex justify-end gap-2 pt-1">
        <button type="button" onClick={onDone} className="inline-flex h-9 items-center rounded-lg border border-border bg-bg-elevated px-3 text-sm font-medium text-fg hover:bg-bg-subtle">
          Cancel
        </button>
        <button type="submit" disabled={busy} className="btn-primary inline-flex h-9 items-center gap-2 rounded-lg px-3 text-sm font-medium disabled:cursor-wait disabled:opacity-70">
          {busy && <Loader2 className="size-4 motion-safe:animate-spin" />}
          {busy ? "Saving…" : "Change password"}
        </button>
      </div>
    </form>
  );
}
