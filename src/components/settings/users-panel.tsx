import { useMemo, useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import type { ColumnDef } from "@tanstack/react-table";
import { AlertTriangle, Copy, KeyRound, Loader2, Lock, MoreHorizontal, RefreshCw, ShieldCheck, Trash2, UserPlus, UsersRound, X } from "lucide-react";
import { toast } from "sonner";
import { ActionButton } from "@/components/layout/page";
import { DataTable } from "@/components/ui/data-table";
import { EmptyState, StatusChip } from "@/components/ui/primitives";
import { useAppSession } from "@/components/auth/use-app-session";
import { createUserAccount, deleteUserAccount, listUserAccounts, updateUserAccount } from "@/lib/aie/server-accounts";
import { ACCOUNT_ROLES, type AccountRole } from "@/lib/aie/accounts/types";
import { PASSWORD_MIN_LENGTH, normalizeUsername, passwordError, usernameError } from "@/lib/aie/accounts/policy";
import { formatDateTime } from "@/lib/aie/format";

type Row = Awaited<ReturnType<typeof listUserAccounts>>[number];

const USERS_KEY = ["user-accounts"] as const;

const field =
  "h-10 w-full rounded-lg border border-border bg-bg-elevated px-3 text-sm text-fg placeholder:text-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/60 disabled:opacity-60";
const menuItem =
  "flex cursor-pointer select-none items-center gap-2.5 rounded-lg px-2 py-2 text-sm text-fg outline-none data-[highlighted]:bg-bg-subtle data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50";

/** 16 characters from an unambiguous alphabet, from the browser's CSPRNG. */
function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = new Uint32Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

function message(err: unknown): string {
  return err instanceof Error ? err.message : "Something went wrong.";
}

/** Settings → Users & access. Administrators manage password accounts; everyone else sees how access works. */
export function UsersPanel() {
  const session = useAppSession();
  const me = session.user;
  const isAdmin = me?.method === "password" && me.role === "admin";

  if (!isAdmin) {
    return (
      <div className="rounded-xl border border-border bg-bg-card p-5">
        <h3 className="flex items-center gap-2 text-base font-medium text-fg">
          <UsersRound className="size-4 text-muted" strokeWidth={1.75} />
          Users & access
        </h3>
        <p className="mt-2 text-sm text-muted">
          Accounts are managed by administrators. You are signed in with{" "}
          {me?.method === "password" ? "a username and password" : me?.method === "sso" ? "single sign-on" : "the local workspace user (sign-in off)"}.
        </p>
        <ul className="mt-4 space-y-2 text-sm text-muted">
          <li>• Username and password accounts are stored in MongoDB (or the local database when MongoDB is not configured).</li>
          <li>• Single sign-on accounts must match AIE_ALLOWED_EMAILS or AIE_ALLOWED_DOMAINS.</li>
        </ul>
      </div>
    );
  }
  return <AdminUsers meId={me.id} storage={session.info?.storage ?? "local"} />;
}

function AdminUsers({ meId, storage }: { meId: string; storage: "mongodb" | "local" }) {
  const qc = useQueryClient();
  const users = useQuery({ queryKey: USERS_KEY, queryFn: () => listUserAccounts(), staleTime: 15_000 });
  const [creating, setCreating] = useState(false);
  const [resetting, setResetting] = useState<Row | null>(null);
  const [deleting, setDeleting] = useState<Row | null>(null);

  const update = useMutation({
    mutationFn: (input: Parameters<typeof updateUserAccount>[0]["data"]) => updateUserAccount({ data: input }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: USERS_KEY }),
    onError: (err) => toast.error(message(err)),
  });

  const rows = users.data ?? [];
  const admins = rows.filter((r) => r.role === "admin" && !r.disabled).length;

  const columns = useMemo<ColumnDef<Row, unknown>[]>(
    () => [
      {
        id: "user",
        header: "User",
        accessorFn: (r) => r.username,
        cell: ({ row: { original: r } }) => (
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <span className="truncate font-medium text-fg">{r.displayName}</span>
              {r.id === meId && <span className="text-xs text-subtle">(you)</span>}
            </div>
            <div className="truncate font-mono text-xs text-muted">
              {r.username}
              {r.email ? ` · ${r.email}` : ""}
            </div>
          </div>
        ),
      },
      {
        id: "role",
        header: "Role",
        accessorFn: (r) => r.role,
        cell: ({ row: { original: r } }) => <span className="text-sm text-fg">{r.role === "admin" ? "Administrator" : "Analyst"}</span>,
      },
      {
        id: "status",
        header: "Status",
        accessorFn: (r) => (r.disabled ? 2 : r.lockedUntil ? 1 : 0),
        cell: ({ row: { original: r } }) =>
          r.disabled ? (
            <StatusChip tone="neutral">Disabled</StatusChip>
          ) : r.lockedUntil ? (
            <StatusChip tone="danger" dot>
              Locked
            </StatusChip>
          ) : r.weakPassword ? (
            <StatusChip tone="warning" dot>
              Short password
            </StatusChip>
          ) : (
            <StatusChip tone="success" dot>
              Active
            </StatusChip>
          ),
      },
      {
        id: "last",
        header: "Last sign-in",
        accessorFn: (r) => r.lastLoginAt ?? "",
        meta: { hideBelow: "md" },
        cell: ({ row: { original: r } }) => <span className="text-sm text-muted">{r.lastLoginAt ? formatDateTime(r.lastLoginAt) : "Never"}</span>,
      },
      {
        id: "sessions",
        header: "Sessions",
        accessorFn: (r) => r.activeSessions,
        meta: { hideBelow: "lg", align: "right" },
        cell: ({ row: { original: r } }) => <span className="tabular-nums text-sm text-muted">{r.activeSessions}</span>,
      },
      {
        id: "actions",
        header: "",
        enableSorting: false,
        meta: { align: "right" },
        cell: ({ row: { original: r } }) => {
          const self = r.id === meId;
          const lastAdmin = r.role === "admin" && !r.disabled && admins <= 1;
          return (
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild>
                <button
                  type="button"
                  aria-label={`Actions for ${r.username}`}
                  className="inline-flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                >
                  <MoreHorizontal className="size-4" />
                </button>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content align="end" sideOffset={6} className="dropdown-liquid-glass z-50 w-56 rounded-xl p-1.5">
                  <DropdownMenu.Item className={menuItem} onSelect={() => setResetting(r)}>
                    <KeyRound className="size-4 text-muted" />
                    {self ? "Set a new password" : "Reset password"}
                  </DropdownMenu.Item>
                  {r.lockedUntil && (
                    <DropdownMenu.Item className={menuItem} onSelect={() => update.mutate({ id: r.id, unlock: true })}>
                      <Lock className="size-4 text-muted" />
                      Unlock
                    </DropdownMenu.Item>
                  )}
                  <DropdownMenu.Item
                    className={menuItem}
                    disabled={self || (r.role === "admin" && lastAdmin)}
                    onSelect={() => update.mutate({ id: r.id, role: r.role === "admin" ? "analyst" : "admin" })}
                  >
                    <ShieldCheck className="size-4 text-muted" />
                    {r.role === "admin" ? "Make analyst" : "Make administrator"}
                  </DropdownMenu.Item>
                  <DropdownMenu.Item
                    className={menuItem}
                    disabled={self || (!r.disabled && lastAdmin)}
                    onSelect={() => update.mutate({ id: r.id, disabled: !r.disabled })}
                  >
                    <RefreshCw className="size-4 text-muted" />
                    {r.disabled ? "Enable" : "Disable and sign out"}
                  </DropdownMenu.Item>
                  <DropdownMenu.Separator className="my-1 h-px bg-border" />
                  <DropdownMenu.Item className={menuItem} disabled={self || lastAdmin} onSelect={() => setDeleting(r)}>
                    <Trash2 className="size-4 text-danger" />
                    <span className="text-danger">Delete</span>
                  </DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
          );
        },
      },
    ],
    [meId, admins, update],
  );

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-border bg-bg-card p-5">
        <div className="flex flex-col gap-3 border-b border-border pb-3 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="flex items-center gap-2 text-base font-medium text-fg">
              <UsersRound className="size-4 text-muted" strokeWidth={1.75} />
              Users & access
            </h3>
            <p className="text-xs text-muted">
              Username and password accounts, stored in {storage === "mongodb" ? "MongoDB" : "the local database (resets on restart without MongoDB)"}. Passwords are kept as
              scrypt hashes.
            </p>
          </div>
          <ActionButton variant="primary" icon={UserPlus} onClick={() => setCreating(true)}>
            Add user
          </ActionButton>
        </div>
        <div className="mt-4">
          {users.isError ? (
            <EmptyState icon={AlertTriangle} title="Users could not be loaded" description={message(users.error)} />
          ) : users.isPending ? (
            <div className="flex items-center gap-2 py-6 text-sm text-muted">
              <Loader2 className="size-4 motion-safe:animate-spin" /> Loading users…
            </div>
          ) : (
            <DataTable data={rows} columns={columns} getRowId={(r) => r.id} initialSorting={[{ id: "user", desc: false }]} dense />
          )}
        </div>
      </div>
      <div className="rounded-xl border border-border bg-bg-card p-5 text-sm text-muted">
        <h4 className="text-sm font-medium text-fg">How access works</h4>
        <ul className="mt-2 space-y-1.5">
          <li>• The administrator account comes from AIE_ADMIN_USERNAME and AIE_ADMIN_PASSWORD. Changing AIE_ADMIN_PASSWORD and restarting resets its password.</li>
          <li>• After 5 failed sign-ins an account is locked for 15 minutes. Sessions last 7 days.</li>
          <li>• Single sign-on stays available for addresses in AIE_ALLOWED_EMAILS or AIE_ALLOWED_DOMAINS.</li>
        </ul>
      </div>

      <CreateUserDialog open={creating} onOpenChange={setCreating} />
      <ResetPasswordDialog row={resetting} self={resetting?.id === meId} onClose={() => setResetting(null)} />
      <DeleteUserDialog row={deleting} onClose={() => setDeleting(null)} />
    </div>
  );
}

function Modal({ open, onOpenChange, title, description, children }: { open: boolean; onOpenChange: (o: boolean) => void; title: string; description: string; children: ReactNode }) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px]" />
        <Dialog.Content className="dropdown-liquid-glass fixed left-1/2 top-1/2 z-50 max-h-[calc(100dvh-2rem)] w-[min(30rem,calc(100vw-2rem))] -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-xl p-5 focus:outline-none">
          <div className="mb-4 flex items-start justify-between gap-4">
            <div>
              <Dialog.Title className="text-base font-semibold text-fg">{title}</Dialog.Title>
              <Dialog.Description className="mt-0.5 text-sm text-muted">{description}</Dialog.Description>
            </div>
            <Dialog.Close aria-label="Close" className="inline-flex size-8 items-center justify-center rounded-lg text-muted hover:bg-bg-subtle hover:text-fg">
              <X className="size-4" />
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function FormError({ error }: { error: string | null }) {
  return (
    <div aria-live="polite">
      {error && (
        <p className="flex items-start gap-2 text-sm text-danger">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" />
          <span>{error}</span>
        </p>
      )}
    </div>
  );
}

function PasswordField({ value, onChange, disabled }: { value: string; onChange: (v: string) => void; disabled?: boolean }) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-fg">Password</span>
        <button type="button" onClick={() => onChange(generatePassword())} disabled={disabled} className="text-xs font-medium text-accent hover:underline">
          Generate
        </button>
      </div>
      <div className="flex gap-2">
        <input type="text" autoComplete="new-password" spellCheck={false} value={value} onChange={(e) => onChange(e.target.value)} disabled={disabled} className={`${field} font-mono`} />
        <button
          type="button"
          aria-label="Copy password"
          disabled={!value}
          onClick={() => void navigator.clipboard?.writeText(value).then(() => toast.success("Password copied"), () => toast.error("Copy failed"))}
          className="inline-flex size-10 shrink-0 items-center justify-center rounded-lg border border-border bg-bg-elevated text-muted hover:text-fg disabled:opacity-50"
        >
          <Copy className="size-4" />
        </button>
      </div>
      <span className="block text-xs text-subtle">At least {PASSWORD_MIN_LENGTH} characters. Share it privately; the user can change it from their profile.</span>
    </div>
  );
}

function CreateUserDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient();
  const [username, setUsername] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [role, setRole] = useState<AccountRole>("analyst");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const create = useMutation({
    mutationFn: () => createUserAccount({ data: { username, displayName: displayName || undefined, email: email || null, role, password } }),
    onSuccess: (user) => {
      toast.success(`Created ${user.username}`);
      void qc.invalidateQueries({ queryKey: USERS_KEY });
      close(false);
    },
    onError: (err) => setError(message(err)),
  });

  function close(o: boolean) {
    onOpenChange(o);
    if (!o) {
      setUsername("");
      setDisplayName("");
      setEmail("");
      setRole("analyst");
      setPassword("");
      setError(null);
    }
  }

  function onSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const u = normalizeUsername(username);
    const problem = usernameError(u) ?? passwordError(password, u);
    if (problem) return setError(problem);
    setError(null);
    create.mutate();
  }

  return (
    <Modal open={open} onOpenChange={close} title="Add user" description="Create a username and password account.">
      <form className="space-y-3.5" onSubmit={onSubmit} noValidate>
        <label className="block space-y-1.5">
          <span className="text-sm font-medium text-fg">Username</span>
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoCapitalize="none" spellCheck={false} placeholder="e.g. j.doe" className={field} />
        </label>
        <div className="grid gap-3.5 sm:grid-cols-2">
          <label className="block space-y-1.5">
            <span className="text-sm font-medium text-fg">Display name</span>
            <input value={displayName} onChange={(e) => setDisplayName(e.target.value)} placeholder="Optional" className={field} />
          </label>
          <label className="block space-y-1.5">
            <span className="text-sm font-medium text-fg">Email</span>
            <input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="Optional" className={field} />
          </label>
        </div>
        <fieldset className="space-y-1.5">
          <legend className="text-sm font-medium text-fg">Role</legend>
          <div className="grid gap-2 sm:grid-cols-2">
            {ACCOUNT_ROLES.map((r) => (
              <label key={r.value} className={`flex cursor-pointer items-start gap-2 rounded-lg border p-2.5 text-sm ${role === r.value ? "border-primary bg-bg-subtle" : "border-border"}`}>
                <input type="radio" name="role" value={r.value} checked={role === r.value} onChange={() => setRole(r.value)} className="mt-0.5 accent-[var(--color-primary)]" />
                <span>
                  <span className="block font-medium text-fg">{r.label}</span>
                  <span className="block text-xs text-muted">{r.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
        <PasswordField value={password} onChange={setPassword} disabled={create.isPending} />
        <FormError error={error} />
        <div className="flex justify-end gap-2 pt-1">
          <ActionButton onClick={() => close(false)}>Cancel</ActionButton>
          <ActionButton type="submit" variant="primary" icon={create.isPending ? Loader2 : UserPlus} disabled={create.isPending}>
            {create.isPending ? "Creating…" : "Create user"}
          </ActionButton>
        </div>
      </form>
    </Modal>
  );
}

function ResetPasswordDialog({ row, self, onClose }: { row: Row | null; self: boolean; onClose: () => void }) {
  const qc = useQueryClient();
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const reset = useMutation({
    mutationFn: () => updateUserAccount({ data: { id: row!.id, password } }),
    onSuccess: () => {
      toast.success(self ? "Password changed" : `Password reset for ${row?.username}; their sessions were signed out.`);
      void qc.invalidateQueries({ queryKey: USERS_KEY });
      close();
    },
    onError: (err) => setError(message(err)),
  });
  function close() {
    setPassword("");
    setError(null);
    onClose();
  }
  return (
    <Modal open={Boolean(row)} onOpenChange={(o) => !o && close()} title={self ? "Set a new password" : `Reset password for ${row?.username ?? ""}`} description={self ? "You stay signed in on this browser." : "Their open sessions are signed out."}>
      <form
        className="space-y-3.5"
        noValidate
        onSubmit={(e) => {
          e.preventDefault();
          const problem = passwordError(password, row?.username);
          if (problem) return setError(problem);
          setError(null);
          reset.mutate();
        }}
      >
        <PasswordField value={password} onChange={setPassword} disabled={reset.isPending} />
        <FormError error={error} />
        <div className="flex justify-end gap-2 pt-1">
          <ActionButton onClick={close}>Cancel</ActionButton>
          <ActionButton type="submit" variant="primary" icon={reset.isPending ? Loader2 : KeyRound} disabled={reset.isPending}>
            {reset.isPending ? "Saving…" : "Save password"}
          </ActionButton>
        </div>
      </form>
    </Modal>
  );
}

function DeleteUserDialog({ row, onClose }: { row: Row | null; onClose: () => void }) {
  const qc = useQueryClient();
  const remove = useMutation({
    mutationFn: () => deleteUserAccount({ data: { id: row!.id } }),
    onSuccess: () => {
      toast.success(`Deleted ${row?.username}`);
      void qc.invalidateQueries({ queryKey: USERS_KEY });
      onClose();
    },
    onError: (err) => toast.error(message(err)),
  });
  return (
    <Modal open={Boolean(row)} onOpenChange={(o) => !o && onClose()} title={`Delete ${row?.username ?? "user"}?`} description="The account and its sessions are removed. This cannot be undone.">
      {row?.bootstrap && (
        <p className="mb-3 text-sm text-muted">This is the environment administrator: it is created again on the next restart while AIE_ADMIN_PASSWORD is set.</p>
      )}
      <div className="flex justify-end gap-2">
        <ActionButton onClick={onClose}>Cancel</ActionButton>
        <button
          type="button"
          disabled={remove.isPending}
          onClick={() => remove.mutate()}
          className="inline-flex h-9 items-center gap-2 rounded-lg px-3 text-sm font-medium text-white disabled:opacity-60"
          style={{ backgroundColor: "var(--color-danger)" }}
        >
          {remove.isPending ? <Loader2 className="size-4 motion-safe:animate-spin" /> : <Trash2 className="size-4" />}
          Delete user
        </button>
      </div>
    </Modal>
  );
}
