import { useState, type ReactNode } from "react";
import { Check, Copy } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/cn";
import type { IdCategory, IdTone } from "@/lib/aie/ids";

export interface IdBadgeProps {
  id: string;
  category?: IdCategory;
  tone?: IdTone;
  label?: string;
  prefixLabel?: string;
  copyable?: boolean;
  showCopyIcon?: boolean;
  size?: "xs" | "sm" | "md";
  title?: string;
  className?: string;
  onClick?: (e: React.MouseEvent) => void;
  children?: ReactNode;
}

export function IdBadge({
  id,
  category,
  tone,
  label,
  prefixLabel,
  copyable = true,
  showCopyIcon = true,
  size = "sm",
  title,
  className,
  onClick,
}: IdBadgeProps) {
  const [copied, setCopied] = useState(false);

  // Derive tone from category if not explicitly provided
  let effectiveTone: IdTone = tone ?? "neutral";
  if (!tone && category) {
    switch (category) {
      case "report":
      case "ingested":
        effectiveTone = "sage";
        break;
      case "duplicate":
        effectiveTone = "warn";
        break;
      case "rejected":
      case "failed":
        effectiveTone = "danger";
        break;
      case "discovered":
        effectiveTone = "accent";
        break;
      case "source":
        effectiveTone = "neutral";
        break;
      default:
        effectiveTone = "neutral";
        break;
    }
  }

  const handleCopy = (e: React.MouseEvent) => {
    e.stopPropagation();
    e.preventDefault();

    if (onClick) {
      onClick(e);
    }

    if (copyable && id) {
      try {
        void navigator.clipboard.writeText(id);
        setCopied(true);
        toast.success(`Copied ID: ${id}`, {
          description: "Unique identifier copied to clipboard for future query/reference.",
          duration: 2000,
        });
        setTimeout(() => setCopied(false), 1800);
      } catch {
        toast.info(id);
      }
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      title={title || `Click to copy ${id}`}
      className={cn(
        "group inline-flex items-center gap-1 font-mono transition-all select-all font-semibold rounded-md border text-left",
        // Sizes
        size === "xs" && "px-1.5 py-0.5 text-[10px] leading-tight",
        size === "sm" && "px-2 py-0.5 text-[11px] leading-snug",
        size === "md" && "px-2.5 py-1 text-xs leading-normal",
        // Interactive state
        copyable && "cursor-pointer hover:shadow-xs active:scale-95",
        // Tones
        effectiveTone === "sage" &&
          "border-emerald-500/25 bg-emerald-950/20 text-emerald-400 hover:border-emerald-500/40 hover:bg-emerald-900/30",
        effectiveTone === "warn" &&
          "border-amber-500/25 bg-amber-950/20 text-amber-400 hover:border-amber-500/40 hover:bg-amber-900/30",
        effectiveTone === "danger" &&
          "border-rose-500/25 bg-rose-950/20 text-rose-400 hover:border-rose-500/40 hover:bg-rose-900/30",
        effectiveTone === "accent" &&
          "border-cyan-500/25 bg-cyan-950/20 text-cyan-400 hover:border-cyan-500/40 hover:bg-cyan-900/30",
        effectiveTone === "neutral" &&
          "border-border/70 bg-bg-elevated/70 text-subtle hover:border-border hover:text-fg hover:bg-bg-subtle",
        className,
      )}
    >
      {prefixLabel && <span className="opacity-60 text-[9px] uppercase tracking-wider">{prefixLabel}</span>}
      <span>{label || id}</span>
      {copyable && showCopyIcon && (
        <span className="opacity-40 group-hover:opacity-100 transition-opacity ml-0.5">
          {copied ? (
            <Check className={cn("text-emerald-400 animate-in zoom-in-50", size === "xs" ? "size-2.5" : "size-3")} />
          ) : (
            <Copy className={size === "xs" ? "size-2.5" : "size-3"} />
          )}
        </span>
      )}
    </button>
  );
}
