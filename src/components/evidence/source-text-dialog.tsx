import * as Dialog from "@radix-ui/react-dialog";
import { useRef } from "react";
import { X } from "lucide-react";
import type { Evidence } from "@/lib/aie/types";
import { resolveRange } from "./evidence-utils";

export function SourceTextDialog({
  text,
  evidence,
  onClose,
}: {
  text: string;
  evidence: Evidence | null;
  onClose: () => void;
}) {
  const markRef = useRef<HTMLElement>(null);
  const range = evidence ? resolveRange(text, evidence) : null;

  return (
    <Dialog.Root open={evidence !== null} onOpenChange={(open) => (!open ? onClose() : undefined)}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/60 backdrop-blur-[1px]" />
        <Dialog.Content
          className="fixed inset-x-3 top-[5vh] z-50 mx-auto flex max-h-[90vh] max-w-3xl flex-col overflow-hidden rounded-xl border border-border bg-bg-card shadow-xl focus:outline-none"
          onOpenAutoFocus={(event) => {
            const mark = markRef.current;
            if (!mark) return;
            event.preventDefault();
            mark.focus({ preventScroll: true });
            requestAnimationFrame(() => mark.scrollIntoView({ block: "center" }));
          }}
        >
          <div className="flex items-start justify-between gap-3 border-b border-border p-4">
            <div className="min-w-0">
              <Dialog.Title className="text-sm font-medium text-fg">Source passage</Dialog.Title>
              <Dialog.Description className="mt-0.5 text-xs text-muted">
                {evidence?.section ? `Section: ${evidence.section} · ` : ""}
                {range
                  ? range.exact
                    ? `Characters ${range.start}–${range.end} of the extracted text`
                    : "Recorded offsets did not match; highlighted the first occurrence of the quote"
                  : "This passage could not be located in the stored extracted text"}
              </Dialog.Description>
            </div>
            <Dialog.Close
              className="inline-flex size-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-bg-subtle hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring/70"
              aria-label="Close"
            >
              <X className="size-4" />
            </Dialog.Close>
          </div>

          {!range && evidence ? (
            <div className="border-b border-border bg-bg-subtle/60 px-4 py-2 text-xs text-muted [overflow-wrap:anywhere]">
              Quote: “{evidence.quote}”
            </div>
          ) : null}

          <div className="min-h-0 flex-1 overflow-y-auto p-4">
            <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed text-muted [overflow-wrap:anywhere]">
              {range ? (
                <>
                  {text.slice(0, range.start)}
                  <mark
                    ref={markRef}
                    tabIndex={-1}
                    className="rounded-sm bg-warn/30 px-0.5 text-fg outline-none ring-1 ring-warn/60 focus-visible:ring-2"
                  >
                    {text.slice(range.start, range.end)}
                  </mark>
                  {text.slice(range.end)}
                </>
              ) : (
                text || "No extracted text stored for this report."
              )}
            </pre>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
