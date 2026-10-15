import type { ComponentType, ReactNode } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { MoreHorizontal } from "lucide-react";
import { cn } from "@/lib/cn";

type IconType = ComponentType<{ className?: string; strokeWidth?: number }>;

export type ActionMenuItem =
  | {
      label: ReactNode;
      icon?: IconType;
      onSelect?: () => void;
      /** External link; opens in a new tab. */
      href?: string;
      disabled?: boolean;
      danger?: boolean;
    }
  | "separator";

const itemCls =
  "flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm text-fg outline-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-40 data-[highlighted]:bg-bg-subtle";

/** Row / header overflow menu, styled like the workspace menu in the app shell. */
export function ActionMenu({
  items,
  label = "More actions",
  trigger,
  align = "end",
  size = "sm",
}: {
  items: ActionMenuItem[];
  label?: string;
  /** Custom trigger content (defaults to a "…" icon button). */
  trigger?: ReactNode;
  align?: "start" | "end";
  size?: "sm" | "md";
}) {
  return (
    <DropdownMenu.Root modal={false}>
      <DropdownMenu.Trigger asChild>
        <button
          type="button"
          aria-label={label}
          title={label}
          onClick={(e) => e.stopPropagation()}
          onKeyDown={(e) => e.stopPropagation()}
          className={cn(
            "inline-flex shrink-0 items-center justify-center gap-2 rounded-lg text-muted transition-colors hover:bg-bg-subtle hover:text-fg data-[state=open]:bg-bg-subtle data-[state=open]:text-fg",
            size === "sm" ? "size-8" : "h-9 border border-border bg-bg-elevated px-3 text-sm font-medium text-fg",
          )}
        >
          {trigger ?? <MoreHorizontal className="size-4" strokeWidth={1.75} />}
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align={align}
          sideOffset={6}
          onClick={(e) => e.stopPropagation()}
          className="z-50 min-w-52 rounded-lg border border-border bg-bg-elevated p-1 shadow-xl"
        >
          {items.map((item, idx) => {
            if (item === "separator") return <DropdownMenu.Separator key={idx} className="my-1 h-px bg-border" />;
            const Icon = item.icon;
            const inner = (
              <>
                {Icon && <Icon className="size-4 text-muted" strokeWidth={1.75} />}
                <span className={cn(item.danger && "text-danger")}>{item.label}</span>
              </>
            );
            if (item.href) {
              return (
                <DropdownMenu.Item key={idx} asChild disabled={item.disabled} className={itemCls}>
                  <a href={item.href} target="_blank" rel="noreferrer">
                    {inner}
                  </a>
                </DropdownMenu.Item>
              );
            }
            return (
              <DropdownMenu.Item key={idx} disabled={item.disabled} onSelect={() => item.onSelect?.()} className={itemCls}>
                {inner}
              </DropdownMenu.Item>
            );
          })}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
