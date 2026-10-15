import type { ComponentType } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/cn";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

export type RowMenuItem = {
  label: string;
  icon?: IconType;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
  hidden?: boolean;
  /** Draw a separator above this item. */
  separated?: boolean;
};

/** Compact "…" row action menu for DataTable rows (styled like the workspace menu). */
export function RowMenu({ items, label = "Row actions" }: { items: RowMenuItem[]; label?: string }) {
  const visible = items.filter((i) => !i.hidden);
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label={label}
          onClick={(e) => e.stopPropagation()}
          className="inline-flex size-8 items-center justify-center rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg data-[state=open]:bg-bg-subtle data-[state=open]:text-fg"
        >
          <MoreHorizontal className="size-4" strokeWidth={1.75} />
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={4}
          onClick={(e) => e.stopPropagation()}
          className="z-50 min-w-44 rounded-lg border border-border bg-bg-elevated p-1 text-sm shadow-xl"
        >
          {visible.map((item) => {
            const Icon = item.icon;
            return (
              <div key={item.label}>
                {item.separated && <DropdownMenu.Separator className="my-1 h-px bg-border" />}
                <DropdownMenu.Item
                  disabled={item.disabled}
                  onSelect={item.onSelect}
                  className={cn(
                    "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 outline-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 data-[highlighted]:bg-bg-subtle",
                    item.danger ? "text-danger" : "text-fg",
                  )}
                >
                  {Icon && <Icon className="size-4" strokeWidth={1.75} />}
                  {item.label}
                </DropdownMenu.Item>
              </div>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

/** Compact on/off switch for table rows. */
export function Switch({
  checked,
  onChange,
  label,
  disabled,
}: {
  checked: boolean;
  onChange: (next: boolean) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      title={label}
      disabled={disabled}
      onClick={(e) => {
        e.stopPropagation();
        onChange(!checked);
      }}
      className={cn(
        "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full border transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "border-accent bg-accent" : "border-border bg-bg-subtle",
      )}
    >
      <span
        className={cn(
          "inline-block size-3.5 rounded-full shadow-sm transition-transform",
          checked ? "translate-x-[18px] bg-accent-fg" : "translate-x-[2px] bg-muted",
        )}
      />
    </button>
  );
}

/** Square initial "favicon" for a source name. */
export function SourceMark({ name }: { name: string }) {
  const initial = (name.trim()[0] ?? "?").toUpperCase();
  return (
    <span
      aria-hidden
      className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-bg-subtle text-xs font-semibold text-muted"
    >
      {initial}
    </span>
  );
}
