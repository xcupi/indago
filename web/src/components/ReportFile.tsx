import { useEffect, useState } from "react";
import { Download } from "lucide-react";
import { Dialog, DialogContent } from "@/components/ui/controls";
import { Alert, Loading } from "@/components/ui/misc";
import { apiResponse } from "@/lib/api";
import type { Report } from "@/lib/types";
import { shortId } from "@/lib/utils";

function reportPath(report: Report) {
  return `/api/reports/${encodeURIComponent(report.id)}/content`;
}

export function ReportDownload({ report }: { report: Report }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function download() {
    setBusy(true);
    setError("");
    try {
      const response = await apiResponse(reportPath(report) + "?download");
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      const name = response.headers.get("Content-Disposition")?.match(/filename="([^"]+)"/i)?.[1];
      link.href = url;
      link.download = name ?? `indago-${report.id}.${report.format === "markdown" ? "md" : report.format}`;
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <span>
      <button type="button" disabled={busy} onClick={download}
        className="inline-flex items-center gap-1 text-[11px] text-muted-foreground hover:underline">
        <Download className="size-3" aria-hidden="true" />
        {busy ? "Downloading…" : "Download"}
      </button>
      {error ? <span role="alert" className="ml-2 text-xs text-red-700">{error}</span> : null}
    </span>
  );
}

// Local previews do not inherit the content endpoint's response headers.
const HTML_POLICY = `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">`;

export function ReportPreview({ report, onClose }: { report: Report; onClose: () => void }) {
  const [content, setContent] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    const request = new AbortController();
    let pdfURL: string | undefined;
    async function load() {
      try {
        const response = await apiResponse(reportPath(report), { signal: request.signal });
        if (report.format === "pdf") {
          const data = await response.blob();
          if ((await data.slice(0, 5).text()) !== "%PDF-") throw new Error("The server did not return a PDF.");
          if (request.signal.aborted) return;
          pdfURL = URL.createObjectURL(new Blob([data], { type: "application/pdf" }));
          setContent(pdfURL);
        } else {
          const source = await response.text();
          if (!request.signal.aborted) setContent(source);
        }
      } catch (e) {
        if (!request.signal.aborted) setError((e as Error).message);
      } finally {
        if (!request.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => {
      request.abort();
      if (pdfURL) URL.revokeObjectURL(pdfURL);
    };
  }, [report]);

  const frameClass = "h-[65vh] w-full rounded-md border border-border bg-white";
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose(); }}>
      <DialogContent title={`Report ${shortId(report.id)}`} description={`${report.format} · ${report.template || "—"}`} className="max-w-5xl">
        <ReportDownload report={report} />
        {loading ? <Loading /> : error ? <Alert>{error}</Alert>
          : report.format === "pdf" ? <iframe title={`PDF report ${report.id}`} src={content} className={frameClass} />
          : report.format === "html" ? (
            <iframe title={`HTML report ${report.id}`} sandbox="" className={frameClass}
              srcDoc={"<!doctype html>" + HTML_POLICY + content.replace(/^\s*<!doctype html>/i, "")} />
          )
          : <pre className="max-h-[65vh] overflow-auto whitespace-pre-wrap break-words rounded-md border border-border bg-muted p-3 text-[11px]">{content}</pre>}
      </DialogContent>
    </Dialog>
  );
}
