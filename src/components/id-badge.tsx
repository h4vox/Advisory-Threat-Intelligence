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
        "group inline-flex items-center gap-1 rounded-md border font-mono font-medium text-left transition-colors select-all",
        // Sizes
        size === "xs" && "px-1.5 py-0.5 text-[10px] leading-tight",
        size === "sm" && "px-2 py-0.5 text-[11px] leading-snug",
        size === "md" && "px-2.5 py-1 text-xs leading-normal",
        // Interactive state
        copyable && "cursor-pointer",
        // Tones
        effectiveTone === "sage" &&
          "border-sage/30 bg-transparent text-sage hover:bg-sage/10",
        effectiveTone === "warn" &&
          "border-warn/30 bg-transparent text-warn hover:bg-warn/10",
        effectiveTone === "danger" &&
          "border-danger/40 bg-transparent text-danger hover:bg-danger/10",
        effectiveTone === "accent" &&
          "border-accent/30 bg-transparent text-accent hover:bg-accent/10",
        effectiveTone === "neutral" &&
          "border-border bg-transparent text-muted hover:bg-bg-subtle hover:text-fg",
        className,
      )}
    >
      {prefixLabel && <span className="font-sans text-[10px] font-normal text-subtle">{prefixLabel}</span>}
      <span>{label || id}</span>
      {copyable && showCopyIcon && (
        <span className="opacity-40 group-hover:opacity-100 transition-opacity ml-0.5">
          {copied ? (
            <Check className={cn("text-sage", size === "xs" ? "size-2.5" : "size-3")} />
          ) : (
            <Copy className={size === "xs" ? "size-2.5" : "size-3"} />
          )}
        </span>
      )}
    </button>
  );
}
