import React, { useState } from "react";
import { Check, Copy, ExternalLink, Terminal } from "lucide-react";
import { cn } from "@/lib/cn";

interface MarkdownViewProps {
  content: string;
  className?: string;
}

export function MarkdownView({ content, className }: MarkdownViewProps) {
  if (!content) return null;

  // Split content into blocks: code fences, tables, headers, lists, paragraphs
  const blocks = parseMarkdownBlocks(content);

  return (
    <div className={cn("space-y-2.5 text-xs text-fg leading-relaxed select-text font-sans w-full max-w-full overflow-hidden break-words", className)}>
      {blocks.map((block, idx) => (
        <React.Fragment key={idx}>{renderBlock(block, idx)}</React.Fragment>
      ))}
    </div>
  );
}

type BlockType =
  | { type: "code"; language: string; code: string }
  | { type: "table"; headers: string[]; rows: string[][] }
  | { type: "header"; level: number; text: string }
  | { type: "list"; ordered: boolean; items: string[] }
  | { type: "blockquote"; text: string }
  | { type: "hr" }
  | { type: "paragraph"; text: string };

function parseMarkdownBlocks(markdown: string): BlockType[] {
  const lines = markdown.split(/\r?\n/);
  const blocks: BlockType[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Horizontal Rule
    if (/^(-{3,}|\*{3,}|_{3,})$/.test(line.trim())) {
      blocks.push({ type: "hr" });
      i++;
      continue;
    }

    // Fenced Code Block: ```lang
    if (line.trim().startsWith("```")) {
      const language = line.trim().slice(3).trim();
      const codeLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].trim().startsWith("```")) {
        codeLines.push(lines[i]);
        i++;
      }
      if (i < lines.length) i++; // skip closing ```
      blocks.push({
        type: "code",
        language: language || "text",
        code: codeLines.join("\n"),
      });
      continue;
    }

    // Table: starts with | and next line has | --- |
    if (
      line.trim().startsWith("|") &&
      line.trim().endsWith("|") &&
      i + 1 < lines.length &&
      lines[i + 1].includes("|") &&
      lines[i + 1].includes("---")
    ) {
      const headerLine = line.trim();
      const headers = headerLine
        .slice(1, -1)
        .split("|")
        .map((h) => h.trim());
      i += 2; // skip header and delimiter line

      const rows: string[][] = [];
      while (i < lines.length && lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|")) {
        const rowCells = lines[i]
          .trim()
          .slice(1, -1)
          .split("|")
          .map((c) => c.trim());
        rows.push(rowCells);
        i++;
      }

      blocks.push({ type: "table", headers, rows });
      continue;
    }

    // Headers: #, ##, ###, ####
    const headerMatch = line.match(/^(#{1,4})\s+(.+)$/);
    if (headerMatch) {
      blocks.push({
        type: "header",
        level: headerMatch[1].length,
        text: headerMatch[2].trim(),
      });
      i++;
      continue;
    }

    // Blockquote: >
    if (line.trim().startsWith(">")) {
      const quoteLines: string[] = [line.replace(/^>\s?/, "")];
      i++;
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        quoteLines.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      blocks.push({ type: "blockquote", text: quoteLines.join(" ") });
      continue;
    }

    // Unordered List (- or *)
    if (/^(\s*)[-*]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^(\s*)[-*]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^(\s*)[-*]\s+/, ""));
        i++;
      }
      blocks.push({ type: "list", ordered: false, items });
      continue;
    }

    // Ordered List (1., 2., etc)
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ""));
        i++;
      }
      blocks.push({ type: "list", ordered: true, items });
      continue;
    }

    // Empty line
    if (!line.trim()) {
      i++;
      continue;
    }

    // Paragraph: collect consecutive text lines
    const pLines: string[] = [line];
    i++;
    while (
      i < lines.length &&
      lines[i].trim() &&
      !lines[i].trim().startsWith("```") &&
      !lines[i].trim().startsWith("#") &&
      !lines[i].trim().startsWith(">") &&
      !/^(\s*)[-*]\s+/.test(lines[i]) &&
      !/^\s*\d+\.\s+/.test(lines[i]) &&
      !(lines[i].trim().startsWith("|") && lines[i].trim().endsWith("|"))
    ) {
      pLines.push(lines[i]);
      i++;
    }
    blocks.push({ type: "paragraph", text: pLines.join(" ") });
  }

  return blocks;
}

function renderBlock(block: BlockType, key: number) {
  switch (block.type) {
    case "hr":
      return <hr className="my-2 border-border/60" />;

    case "header": {
      if (block.level === 1) {
        return (
          <h1 className="text-sm font-bold text-fg pt-2 pb-0.5 border-b border-border/50 flex items-center gap-1.5 break-words">
            {renderInline(block.text)}
          </h1>
        );
      }
      if (block.level === 2) {
        return (
          <h2 className="text-xs font-semibold text-fg pt-1.5 pb-0.5 text-accent flex items-center gap-1 break-words">
            {renderInline(block.text)}
          </h2>
        );
      }
      return (
        <h3 className="text-xs font-semibold text-fg/90 pt-1 break-words">
          {renderInline(block.text)}
        </h3>
      );
    }

    case "blockquote":
      return (
        <blockquote className="pl-3 border-l-2 border-accent/60 text-subtle italic bg-accent/[0.03] py-1 rounded-r-md break-words">
          {renderInline(block.text)}
        </blockquote>
      );

    case "list":
      if (block.ordered) {
        return (
          <ol className="list-decimal list-outside pl-4 space-y-1">
            {block.items.map((item, idx) => (
              <li key={idx} className="text-muted leading-relaxed break-words">
                {renderInline(item)}
              </li>
            ))}
          </ol>
        );
      }
      return (
        <ul className="list-disc list-outside pl-4 space-y-1">
          {block.items.map((item, idx) => (
            <li key={idx} className="text-muted leading-relaxed break-words">
              {renderInline(item)}
            </li>
          ))}
        </ul>
      );

    case "table":
      return <MarkdownTable headers={block.headers} rows={block.rows} />;

    case "code":
      return <MarkdownCodeBlock code={block.code} language={block.language} />;

    case "paragraph":
      return (
        <p className="text-muted leading-relaxed break-words">
          {renderInline(block.text)}
        </p>
      );
  }
}

function MarkdownCodeBlock({ code, language }: { code: string; language: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="my-2 max-w-full rounded-xl border border-border/80 bg-black/80 overflow-hidden font-mono text-[11px] shadow-xs">
      <div className="flex items-center justify-between px-3 py-1.5 bg-white/[0.06] border-b border-white/[0.08] text-[10px] text-subtle">
        <span className="flex items-center gap-1 font-mono uppercase tracking-wider text-accent/80">
          <Terminal className="size-3" />
          {language || "sh"}
        </span>
        <button
          type="button"
          onClick={handleCopy}
          className="flex items-center gap-1 hover:text-fg transition-colors cursor-pointer"
        >
          {copied ? <Check className="size-3 text-emerald-400" /> : <Copy className="size-3" />}
          <span>{copied ? "Copied" : "Copy"}</span>
        </button>
      </div>
      <pre className="p-3 overflow-x-auto max-w-full text-emerald-300/90 leading-normal selection:bg-accent/30 whitespace-pre-wrap break-all">
        <code>{code}</code>
      </pre>
    </div>
  );
}

function MarkdownTable({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="my-2 w-full max-w-full overflow-x-auto rounded-xl border border-border/80 bg-bg-card/50 shadow-xs">
      <table className="w-full min-w-full text-left border-collapse text-[11px] table-fixed">
        <thead>
          <tr className="border-b border-border/80 bg-bg-subtle/80">
            {headers.map((h, idx) => (
              <th
                key={idx}
                className="px-2.5 py-1.5 font-semibold text-fg font-mono uppercase text-[9.5px] tracking-wider whitespace-normal break-words"
              >
                {renderInline(h)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border/40">
          {rows.map((row, rIdx) => (
            <tr
              key={rIdx}
              className="hover:bg-accent/[0.04] transition-colors odd:bg-transparent even:bg-bg-subtle/30"
            >
              {row.map((cell, cIdx) => (
                <td key={cIdx} className="px-2.5 py-1.5 text-muted leading-relaxed font-sans whitespace-normal break-words">
                  {renderInline(cell)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/**
 * Inline formatting parser for bold, italic, inline code, and links
 */
function renderInline(text: string): React.ReactNode {
  if (!text) return null;

  // Split by inline code, bold, links
  const regex = /(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*|\[[^\]]+\]\([^)]+\)|T\d{4}(?:\.\d{3})?)/g;
  const parts = text.split(regex);

  return parts.map((part, idx) => {
    if (!part) return null;

    // Inline code: `code`
    if (part.startsWith("`") && part.endsWith("`") && part.length >= 2) {
      const code = part.slice(1, -1);
      return (
        <code
          key={idx}
          className="font-mono text-[10.5px] px-1.5 py-0.5 rounded bg-bg-elevated border border-border/80 text-cyan-300 font-medium"
        >
          {code}
        </code>
      );
    }

    // MITRE Technique ID without backticks: T1059.001
    if (/^T\d{4}(?:\.\d{3})?$/.test(part)) {
      return (
        <span
          key={idx}
          className="font-mono text-[10px] px-1 py-0.2 rounded bg-accent/15 border border-accent/30 text-accent font-semibold"
        >
          {part}
        </span>
      );
    }

    // Bold: **text**
    if (part.startsWith("**") && part.endsWith("**") && part.length >= 4) {
      return (
        <strong key={idx} className="font-semibold text-fg">
          {part.slice(2, -2)}
        </strong>
      );
    }

    // Italic: *text*
    if (part.startsWith("*") && part.endsWith("*") && part.length >= 2) {
      return (
        <em key={idx} className="italic text-fg/90">
          {part.slice(1, -1)}
        </em>
      );
    }

    // Link: [text](url)
    const linkMatch = part.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
    if (linkMatch) {
      return (
        <a
          key={idx}
          href={linkMatch[2]}
          target="_blank"
          rel="noreferrer"
          className="text-accent hover:underline inline-flex items-center gap-0.5"
        >
          <span>{linkMatch[1]}</span>
          <ExternalLink className="size-2.5" />
        </a>
      );
    }

    return <span key={idx}>{part}</span>;
  });
}
