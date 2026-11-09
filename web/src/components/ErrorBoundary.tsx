import { Component, type ErrorInfo, type ReactNode } from "react";
import { AlertTriangle } from "lucide-react";

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

/**
 * Page-level boundary: a panel that trips on an unexpected API shape must not
 * unmount the whole SPA and leave a blank page. The operator gets the error and
 * a reload control; navigation in the sidebar keeps working.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ui panel crashed", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="mx-auto max-w-2xl rounded-lg border border-red-900/60 bg-red-950/20 p-5">
        <div className="flex items-center gap-2 text-sm font-semibold text-red-200">
          <AlertTriangle className="size-4" /> This view failed to render
        </div>
        <p className="mt-2 text-xs text-red-200/80">
          The rest of the dashboard is still usable — pick another view, or reload after the server
          data changes.
        </p>
        <pre className="mono mt-3 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded-md border border-red-900/40 bg-zinc-950/70 p-3 text-[11px] text-red-200/80">
          {this.state.error.message}
        </pre>
        <div className="mt-3 flex gap-2">
          <button
            className="rounded-md bg-zinc-800 px-3 py-1.5 text-xs text-zinc-100 hover:bg-zinc-700"
            onClick={() => {
              this.setState({ error: null });
              window.location.reload();
            }}
          >
            Reload
          </button>
          <button
            className="rounded-md border border-zinc-700 px-3 py-1.5 text-xs text-zinc-300 hover:bg-zinc-800"
            onClick={() => this.setState({ error: null })}
          >
            Dismiss
          </button>
        </div>
      </div>
    );
  }
}
