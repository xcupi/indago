import { useEffect, useState } from "react";
import { Button } from "@/components/ui/button";

/**
 * Client-side pagination for lists whose API already returns the full array.
 * The page is clamped when a filter makes the list shorter, so a stale page
 * number cannot leave the table blank.
 */
export function usePagination<T>(rows: T[], initialPageSize = 25) {
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));

  useEffect(() => {
    if (page > pages) setPage(pages);
  }, [page, pages]);

  const safePage = Math.min(page, pages);
  const start = (safePage - 1) * pageSize;
  return {
    page: safePage,
    setPage,
    pageSize,
    setPageSize,
    pages,
    total: rows.length,
    start,
    rows: rows.slice(start, start + pageSize),
  };
}

export function Pagination({
  page,
  pages,
  pageSize,
  total,
  start,
  setPage,
  setPageSize,
}: {
  page: number;
  pages: number;
  pageSize: number;
  total: number;
  start: number;
  setPage: (page: number) => void;
  setPageSize: (size: number) => void;
}) {
  if (total === 0) return null;
  const end = Math.min(start + pageSize, total);
  return (
    <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border px-3 py-2 text-[11px] text-muted-foreground">
      <span>
        Showing {start + 1}–{end} of {total}
      </span>
      <div className="flex flex-wrap items-center gap-2">
        <label className="flex items-center gap-1">
          Rows
          <select
            className="h-7 rounded-md border border-border bg-background px-1.5 text-[11px] text-foreground"
            value={pageSize}
            onChange={(e) => {
              setPageSize(Number(e.target.value));
              setPage(1);
            }}
          >
            {[10, 25, 50, 100].map((n) => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </label>
        <span>Page {page} / {pages}</span>
        <Button size="sm" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>
          Previous
        </Button>
        <Button size="sm" variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)}>
          Next
        </Button>
      </div>
    </div>
  );
}
