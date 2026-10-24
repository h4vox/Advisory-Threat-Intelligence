import { Children, Fragment, isValidElement, useMemo, type ReactElement, type ReactNode } from "react";
import * as SelectPrimitive from "@radix-ui/react-select";
import { Check, ChevronDown, ChevronUp } from "lucide-react";
import { cn } from "@/lib/cn";

/**
 * Themed replacement for the native `<select>`.
 *
 * Native option lists are drawn by the OS and ignore the app's tokens (a white
 * list over the dark UI, wrong colours in light / Liquid glass), so every
 * dropdown goes through this Radix Select instead. The list is portalled under
 * <body>, so it inherits the theme tokens set on <html> and sits above drawers
 * and modals (z-50).
 *
 * Options come from `options` or from native-style `<option>` / `<optgroup>`
 * children, so call sites migrate with minimal markup changes. Values are
 * strings: callers convert numbers with String() / Number(). An empty string
 * is a valid value (e.g. "All" / "none"); it is mapped to an internal sentinel
 * because Radix reserves "" for "no selection".
 */

export type SelectOption = {
  value: string;
  label: ReactNode;
  disabled?: boolean;
  /** Group heading; consecutive options with the same group render under one heading. */
  group?: string;
  /** Muted second line shown in the list only (not in the trigger). */
  description?: ReactNode;
  /** Plain text for typeahead when `label` is not a string. */
  textValue?: string;
};

export type SelectProps = {
  value: string;
  onValueChange: (value: string) => void;
  options?: SelectOption[];
  /** Native-style `<option>` / `<optgroup>` elements (used when `options` is not given). */
  children?: ReactNode;
  /** Shown when `value` matches no option. Without it, the first enabled option is shown (like a native select). */
  placeholder?: ReactNode;
  /** Put on the trigger so a `<label htmlFor>` can point at it. */
  id?: string;
  name?: string;
  title?: string;
  disabled?: boolean;
  required?: boolean;
  "aria-label"?: string;
  "aria-labelledby"?: string;
  "aria-describedby"?: string;
  /** `md` = h-9 (default form/filter control), `sm` = h-8 (compact pager / inline controls). */
  size?: "sm" | "md";
  /** Classes for the trigger (width, height, background, text size…). */
  className?: string;
  /** Extra classes for the floating list. */
  contentClassName?: string;
  align?: "start" | "center" | "end";
};

const EMPTY_VALUE = "__aie_select_empty__";
const toInternal = (v: string) => (v === "" ? EMPTY_VALUE : v);
const fromInternal = (v: string) => (v === EMPTY_VALUE ? "" : v);

function textOf(node: ReactNode): string {
  if (node == null || typeof node === "boolean") return "";
  if (typeof node === "string" || typeof node === "number") return String(node);
  if (Array.isArray(node)) return node.map(textOf).join("");
  if (isValidElement<{ children?: ReactNode }>(node)) return textOf(node.props.children);
  return "";
}

type OptionProps = { value?: string | number | readonly string[]; disabled?: boolean; children?: ReactNode; label?: string };

/** Turn `<option>` / `<optgroup>` children (fragments and arrays included) into options. */
function parseChildren(children: ReactNode, group?: string, groupDisabled?: boolean): SelectOption[] {
  const out: SelectOption[] = [];
  Children.forEach(children, (child) => {
    if (!isValidElement(child)) return;
    const el = child as ReactElement<OptionProps>;
    if (el.type === Fragment) {
      out.push(...parseChildren(el.props.children, group, groupDisabled));
    } else if (el.type === "optgroup") {
      out.push(...parseChildren(el.props.children, el.props.label ?? "", groupDisabled || !!el.props.disabled));
    } else if (el.type === "option") {
      const text = textOf(el.props.children);
      out.push({
        value: el.props.value === undefined ? text : String(el.props.value),
        label: el.props.children,
        disabled: groupDisabled || !!el.props.disabled,
        group,
        textValue: text,
      });
    }
  });
  return out;
}

/** Split options into runs that share a group, keeping their order. */
function groupRuns(options: SelectOption[]) {
  const runs: { group?: string; items: SelectOption[] }[] = [];
  for (const o of options) {
    const last = runs[runs.length - 1];
    if (last && last.group === o.group) last.items.push(o);
    else runs.push({ group: o.group, items: [o] });
  }
  return runs;
}

const TRIGGER_SIZE = {
  md: "h-9 px-3 text-sm",
  sm: "h-8 px-2 text-sm",
} as const;

export function Select({
  value,
  onValueChange,
  options: optionsProp,
  children,
  placeholder,
  id,
  name,
  title,
  disabled,
  required,
  "aria-label": ariaLabel,
  "aria-labelledby": ariaLabelledBy,
  "aria-describedby": ariaDescribedBy,
  size = "md",
  className,
  contentClassName,
  align = "start",
}: SelectProps) {
  const options = useMemo(() => optionsProp ?? parseChildren(children), [optionsProp, children]);
  const selected = options.find((o) => o.value === value);
  const fallback = selected ?? (placeholder === undefined ? options.find((o) => !o.disabled) : undefined);
  // With no match and a placeholder, hand Radix "" so it shows the placeholder (and sets data-placeholder).
  const rootValue = !selected && placeholder !== undefined ? "" : toInternal(value);
  const runs = groupRuns(options);

  return (
    <SelectPrimitive.Root
      value={rootValue}
      onValueChange={(v) => onValueChange(fromInternal(v))}
      disabled={disabled}
      name={name}
      required={required}
    >
      <SelectPrimitive.Trigger
        id={id}
        title={title}
        aria-label={ariaLabel}
        aria-labelledby={ariaLabelledBy}
        aria-describedby={ariaDescribedBy}
        data-slot="select-trigger"
        className={cn(
          "inline-flex min-w-0 items-center justify-between gap-2 rounded-lg border border-border bg-bg-elevated text-left text-fg transition-colors",
          "hover:border-border-strong focus-visible:border-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring",
          "data-[state=open]:border-accent data-[placeholder]:text-subtle disabled:cursor-not-allowed disabled:opacity-50",
          TRIGGER_SIZE[size],
          className,
        )}
      >
        {/* Every label sits in the same grid cell (invisibly) so the trigger is as wide as the
            widest option, like a native select, and does not jump when the selection changes. */}
        <span className="grid min-w-0 flex-1 grid-cols-[minmax(0,1fr)]">
          <span className="col-start-1 row-start-1 truncate">
            <SelectPrimitive.Value placeholder={placeholder}>{fallback?.label}</SelectPrimitive.Value>
          </span>
          {placeholder !== undefined && (
            <span aria-hidden className="invisible col-start-1 row-start-1 overflow-hidden whitespace-nowrap">
              {placeholder}
            </span>
          )}
          {options.map((o, i) => (
            <span key={`${i}:${o.value}`} aria-hidden className="invisible col-start-1 row-start-1 overflow-hidden whitespace-nowrap">
              {o.label}
            </span>
          ))}
        </span>
        <SelectPrimitive.Icon asChild>
          <ChevronDown className={cn("shrink-0 text-subtle", size === "sm" ? "size-3.5" : "size-4")} strokeWidth={1.75} />
        </SelectPrimitive.Icon>
      </SelectPrimitive.Trigger>
      <SelectPrimitive.Portal>
        <SelectPrimitive.Content
          position="popper"
          align={align}
          sideOffset={4}
          collisionPadding={8}
          className={cn(
            "select-content dropdown-liquid-glass relative z-[60] flex max-h-[min(22rem,var(--radix-select-content-available-height))] min-w-[var(--radix-select-trigger-width)] max-w-[min(32rem,var(--radix-select-content-available-width))] flex-col overflow-hidden rounded-lg text-sm text-fg",
            contentClassName,
          )}
        >
          <SelectPrimitive.ScrollUpButton className="flex h-6 shrink-0 cursor-default items-center justify-center text-muted">
            <ChevronUp className="size-4" strokeWidth={1.75} />
          </SelectPrimitive.ScrollUpButton>
          <SelectPrimitive.Viewport className="p-1">
            {runs.map((run, ri) => {
              const items = run.items.map((o, i) => (
                <SelectPrimitive.Item
                  key={`${ri}:${i}:${o.value}`}
                  value={toInternal(o.value)}
                  disabled={o.disabled}
                  textValue={o.textValue ?? (typeof o.label === "string" ? o.label : textOf(o.label))}
                  className={cn(
                    "relative flex w-full cursor-pointer select-none items-start rounded-md py-1.5 pl-2 pr-8 text-fg outline-none",
                    "data-[highlighted]:bg-bg-subtle data-[state=checked]:font-medium",
                    "data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50",
                  )}
                >
                  <span className="min-w-0 flex-1 break-words">
                    <SelectPrimitive.ItemText>{o.label}</SelectPrimitive.ItemText>
                    {o.description != null && <span className="mt-0.5 block text-xs font-normal text-muted">{o.description}</span>}
                  </span>
                  <SelectPrimitive.ItemIndicator className="absolute right-2 top-2 inline-flex items-center text-accent">
                    <Check className="size-3.5" strokeWidth={2.25} />
                  </SelectPrimitive.ItemIndicator>
                </SelectPrimitive.Item>
              ));
              if (run.group === undefined) return <Fragment key={`run-${ri}`}>{items}</Fragment>;
              return (
                <SelectPrimitive.Group key={`run-${ri}`}>
                  {ri > 0 && <SelectPrimitive.Separator className="mx-1 my-1 h-px bg-border" />}
                  <SelectPrimitive.Label className="px-2 pb-1 pt-1.5 text-[11px] font-medium uppercase tracking-wide text-subtle">
                    {run.group}
                  </SelectPrimitive.Label>
                  {items}
                </SelectPrimitive.Group>
              );
            })}
          </SelectPrimitive.Viewport>
          <SelectPrimitive.ScrollDownButton className="flex h-6 shrink-0 cursor-default items-center justify-center text-muted">
            <ChevronDown className="size-4" strokeWidth={1.75} />
          </SelectPrimitive.ScrollDownButton>
        </SelectPrimitive.Content>
      </SelectPrimitive.Portal>
    </SelectPrimitive.Root>
  );
}
