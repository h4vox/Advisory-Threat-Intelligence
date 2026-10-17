import { Fragment } from "react";

function escapeRe(s: string) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Renders text with the given terms highlighted (case-insensitive, longest first, whole words). */
export function Highlight({ text, terms }: { text: string; terms: string[] }) {
  const list = Array.from(new Set(terms.map((t) => t.trim()).filter((t) => t.length >= 2))).sort((a, b) => b.length - a.length);
  if (!text || list.length === 0) return <>{text}</>;
  const re = new RegExp(`(?<![A-Za-z0-9])(${list.map(escapeRe).join("|")})(?![A-Za-z0-9])`, "gi");
  const parts = text.split(re);
  return (
    <>
      {parts.map((p, i) =>
        i % 2 === 1 ? (
          <mark key={i} className="rounded-sm bg-[color-mix(in_oklab,var(--color-primary)_20%,transparent)] px-0.5 font-medium text-fg">
            {p}
          </mark>
        ) : (
          <Fragment key={i}>{p}</Fragment>
        ),
      )}
    </>
  );
}
