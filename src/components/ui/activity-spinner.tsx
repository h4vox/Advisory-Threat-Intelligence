import React from "react";
import { cn } from "@/lib/cn";

export interface ActivitySpinnerProps {
  className?: string;
  size?: "xs" | "sm" | "md" | "lg";
  variant?: "radial" | "ring" | "dots";
  color?: string;
}

const SIZE_MAP = {
  xs: "size-3",
  sm: "size-4",
  md: "size-5",
  lg: "size-7",
};

/**
 * Universal Activity Spinner
 * Supports 3 themes:
 * - 'radial': 12-blade radial indicator with stepped rotation & graduated blade opacity
 * - 'ring': Smooth rotating gradient activity ring
 * - 'dots': Kinetic pulsing triple dots
 */
export function ActivitySpinner({
  className,
  size = "sm",
  variant,
  color = "currentColor",
}: ActivitySpinnerProps) {
  const sizeClass = SIZE_MAP[size] || SIZE_MAP.sm;

  const [activeVariant, setActiveVariant] = React.useState<"radial" | "ring" | "dots">(() => {
    if (variant) {
      return variant;
    }
    if (typeof window !== "undefined") {
      const saved = (localStorage.getItem("aie_spinner_variant") as string | null) || "radial";
      return (saved as "radial" | "ring" | "dots") || "radial";
    }
    return "radial";
  });

  React.useEffect(() => {
    if (variant) {
      setActiveVariant(variant);
      return;
    }
    const updateVariant = () => {
      const saved = (localStorage.getItem("aie_spinner_variant") as string | null) || "radial";
      setActiveVariant((saved as "radial" | "ring" | "dots") || "radial");
    };
    window.addEventListener("aie-spinner-changed", updateVariant);
    return () => window.removeEventListener("aie-spinner-changed", updateVariant);
  }, [variant]);

  if (activeVariant === "ring") {
    return (
      <div
        role="status"
        aria-label="Loading"
        className={cn(
          "relative inline-flex items-center justify-center animate-spin shrink-0 aspect-square",
          sizeClass,
          className
        )}
        style={{ animationDuration: "0.85s" }}
      >
        <svg viewBox="0 0 24 24" fill="none" className="w-full h-full">
          <circle
            cx="12"
            cy="12"
            r="9.5"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            className="opacity-20"
          />
          <path
            d="M12 2.5 A 9.5 9.5 0 0 1 21.5 12"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            className="opacity-95"
          />
        </svg>
      </div>
    );
  }

  if (activeVariant === "dots") {
    return (
      <div role="status" aria-label="Loading" className={cn("inline-flex items-center gap-1 shrink-0", className)}>
        <span className="size-1.5 rounded-full bg-current animate-bounce [animation-delay:-0.3s]" />
        <span className="size-1.5 rounded-full bg-current animate-bounce [animation-delay:-0.15s]" />
        <span className="size-1.5 rounded-full bg-current animate-bounce" />
      </div>
    );
  }

  // 12-Blade Radial Spinner
  const blades = [
    { rotate: 0, opacity: 1.0 },
    { rotate: 30, opacity: 0.92 },
    { rotate: 60, opacity: 0.84 },
    { rotate: 90, opacity: 0.75 },
    { rotate: 120, opacity: 0.65 },
    { rotate: 150, opacity: 0.55 },
    { rotate: 180, opacity: 0.45 },
    { rotate: 210, opacity: 0.35 },
    { rotate: 240, opacity: 0.25 },
    { rotate: 270, opacity: 0.18 },
    { rotate: 300, opacity: 0.12 },
    { rotate: 330, opacity: 0.08 },
  ];

  return (
    <div
      role="status"
      aria-label="Loading"
      className={cn(
        "relative inline-flex items-center justify-center shrink-0 aspect-square",
        sizeClass,
        className
      )}
    >
      <svg
        viewBox="0 0 24 24"
        className="w-full h-full animate-activity-radial"
      >
        {blades.map((b, i) => (
          <line
            key={i}
            x1="12"
            y1="2.5"
            x2="12"
            y2="6.5"
            stroke={color}
            strokeWidth="2"
            strokeLinecap="round"
            transform={`rotate(${b.rotate} 12 12)`}
            style={{ opacity: b.opacity }}
          />
        ))}
      </svg>
    </div>
  );
}
