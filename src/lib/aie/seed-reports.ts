/**
 * Demo / placeholder reports have been removed. AIE shows only real intelligence that its crawler and
 * connectors actually retrieve — never dummy or test data in the library or anywhere else.
 *
 * This export is intentionally kept (empty) so existing imports stay valid. `ensureSeeded` in
 * server.ts purges any legacy seed rows (ids starting `rpt_seed_`, or `ingestOrigin: "seed"`) that
 * older builds inserted on first run, so databases created before this change are cleaned up too.
 */
export const SEED_REPORTS: {
  id: string;
  sourceId: string;
  title: string;
  url: string;
  publishedAt: string;
  text: string;
}[] = [];
