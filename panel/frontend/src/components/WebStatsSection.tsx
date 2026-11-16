import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api";
import { timeAgo, formatDate } from "../utils/format";
import { DbIpAttribution } from "./WebStatsServerCard";

// ── Shapes (08-stats-web-contrats.md B-3) ────────────────────────────────────

/** `GET /api/sites/{id}/stats/state`, and the answer of `POST .../stats/refresh`. */
export interface SiteWebStats {
  installed: boolean;
  updated_at: string | null;
  error: string | null;
  running: boolean;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/** What the report fetch ended with. */
type Report =
  | { kind: "idle" }
  | { kind: "loading" }
  | { kind: "ready"; html: string }
  | { kind: "none" }
  | { kind: "error"; text: string };

/**
 * `GET /api/sites/{id}/stats/report` returns text/html, so it cannot go
 * through `api.ts` (which parses JSON). Same headers and same 401 rule as
 * `api.ts`: the session marker alone may send the user to /login.
 */
async function fetchReport(siteId: string): Promise<Report> {
  const headers: Record<string, string> = { "X-Requested-With": "DockPanel" };
  const serverId = localStorage.getItem("dp-active-server");
  if (serverId) headers["X-Server-Id"] = serverId;

  const res = await fetch(`/api/sites/${encodeURIComponent(siteId)}/stats/report`, {
    credentials: "same-origin",
    headers,
  });
  if (res.ok) return { kind: "ready", html: await res.text() };

  const data = (await res.json().catch(() => ({}))) as { error?: string; code?: string };
  if (res.status === 401 && data.code === "session_invalid") {
    window.location.href = "/login";
  }
  if (res.status === 404) return { kind: "none" };
  let text = data.error || `Could not load the report (${res.status})`;
  if (data.code === "agent_unreachable") text = "Agent offline - the CyberHunter - Panel agent is not responding.";
  return { kind: "error", text };
}

/**
 * The GoAccess report. It holds strings sent by visitors (URLs, referrers,
 * User-Agents), so it only ever runs in a sandbox WITHOUT allow-same-origin:
 * its scripts get an opaque origin and cannot reach the panel, its cookies
 * or its API. Never give this frame a `src` pointing at the API, and never
 * open the report in a tab (blob or window.open): a tab opened from the
 * panel takes the panel's origin.
 */
function ReportFrame({ html, className }: { html: string; className: string }) {
  return <iframe sandbox="allow-scripts" srcDoc={html} title="Web statistics" className={className} />;
}

interface Props {
  siteId: string;
  domain: string;
  /** Admin: the "not installed" state links to Settings -> Services. */
  isAdmin: boolean;
}

/**
 * Site detail -> Web statistics: the site's GoAccess report (updated every
 * hour by the backend), "Refresh" for an immediate run, full screen and
 * download. Collapsed by default: the report is only fetched when opened.
 */
export default function WebStatsSection({ siteId, domain, isAdmin }: Props) {
  const [open, setOpen] = useState(false);
  const [stats, setStats] = useState<SiteWebStats | null>(null);
  const [statsError, setStatsError] = useState("");
  const [report, setReport] = useState<Report>({ kind: "idle" });
  const [refreshing, setRefreshing] = useState(false);
  const [msg, setMsg] = useState("");
  const [fullScreen, setFullScreen] = useState(false);
  const closeRef = useRef<HTMLButtonElement>(null);

  const loadStats = useCallback(async () => {
    try {
      const s = await api.get<SiteWebStats>(`/sites/${siteId}/stats/state`);
      setStats(s);
      setStatsError("");
      return s;
    } catch (e) {
      setStatsError(errText(e, "Could not read the web statistics state"));
      return null;
    }
  }, [siteId]);

  const loadReport = useCallback(async () => {
    setReport((r) => (r.kind === "ready" ? r : { kind: "loading" }));
    try {
      setReport(await fetchReport(siteId));
    } catch (e) {
      setReport({ kind: "error", text: errText(e, "Could not load the report") });
    }
  }, [siteId]);

  // The state is cheap and feeds the header ("Updated 23 min ago").
  useEffect(() => {
    setStats(null);
    setReport({ kind: "idle" });
    setMsg("");
    loadStats();
  }, [loadStats]);

  // The report can weigh a few MB: fetched on first open only.
  useEffect(() => {
    if (open && stats?.installed && report.kind === "idle") loadReport();
  }, [open, stats?.installed, report.kind, loadReport]);

  // A run in progress (hourly pass, the first run after install, or a
  // Refresh from another tab): follow it, then reload the report it produced.
  const running = stats?.running ?? false;
  useEffect(() => {
    if (!running) return;
    const t = setInterval(async () => {
      const s = await loadStats();
      if (s && !s.running && s.installed && open) loadReport();
    }, 15000);
    return () => clearInterval(t);
  }, [running, open, loadStats, loadReport]);

  const refresh = async () => {
    setRefreshing(true);
    setMsg("");
    try {
      const s = await api.post<SiteWebStats>(`/sites/${siteId}/stats/refresh`);
      setStats(s);
      if (s.installed) {
        setOpen(true);
        await loadReport();
      }
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        setMsg("A statistics run is already running for this site");
      } else if (e instanceof ApiError && e.status === 412) {
        setMsg("Web statistics not installed");
        loadStats();
      } else {
        setMsg(errText(e, "Statistics run failed"));
        // The run is synchronous and long: the request can die on the way
        // while the run goes on. Re-read the state rather than guess.
        loadStats();
      }
    } finally {
      setRefreshing(false);
    }
  };

  const html = report.kind === "ready" ? report.html : null;

  // "Download": the text already loaded, saved through an <a download> on a
  // blob URL. The link is clicked without navigating anywhere, then revoked.
  const download = () => {
    if (!html) return;
    // octet-stream: a browser that ignored `download` could not render it.
    const url = URL.createObjectURL(new Blob([html], { type: "application/octet-stream" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${domain}-stats.html`;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60000);
  };

  // Full screen: Escape closes it (when focus is in the panel, not inside the
  // frame, whose key events never reach this page), so does "Close".
  useEffect(() => {
    if (!fullScreen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setFullScreen(false);
    };
    window.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    closeRef.current?.focus();
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [fullScreen]);

  useEffect(() => {
    if (!html) setFullScreen(false);
  }, [html]);

  const installed = stats?.installed ?? false;
  const btn =
    "px-3 py-1.5 bg-dark-700 text-dark-100 rounded-lg text-xs font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors";

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
      <div className="px-5 py-4 flex items-center justify-between gap-3 flex-wrap">
        <button
          onClick={() => setOpen(!open)}
          aria-expanded={open}
          className="flex items-center gap-3 min-w-0 text-left hover:opacity-80 transition-opacity"
        >
          <svg
            className={`w-4 h-4 text-dark-300 shrink-0 transition-transform ${open ? "rotate-180" : ""}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            strokeWidth={2}
          >
            <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
          </svg>
          <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Web statistics</h2>
          {installed && (
            <span className="text-xs text-dark-300">
              {stats?.updated_at ? (
                <span title={formatDate(stats.updated_at)}>Updated {timeAgo(stats.updated_at)}</span>
              ) : (
                "Not computed yet"
              )}
            </span>
          )}
        </button>
        {installed && (
          <div className="flex items-center gap-2 flex-wrap">
            <button onClick={refresh} disabled={refreshing || stats?.running} className={btn}>
              {refreshing || stats?.running ? "Computing..." : "Refresh"}
            </button>
            {html && (
              <>
                <button onClick={() => setFullScreen(true)} className={btn}>
                  Full screen
                </button>
                <button onClick={download} className={btn}>
                  Download
                </button>
              </>
            )}
          </div>
        )}
        {(stats?.error || msg) && (
          <div className="w-full space-y-1">
            {stats?.error && <p className="text-xs text-danger-400">Last statistics run failed: {stats.error}</p>}
            {msg && <p className="text-xs text-danger-400">{msg}</p>}
          </div>
        )}
      </div>

      {open && (
        <div className="border-t border-dark-600 p-5 space-y-2">
          {statsError ? (
            <p className="text-xs text-danger-400">{statsError}</p>
          ) : !stats ? (
            <p className="text-sm text-dark-300">Loading...</p>
          ) : !installed ? (
            <p className="text-sm text-dark-300">
              {isAdmin ? (
                <Link to="/settings?tab=services" className="text-accent-400 hover:text-accent-300">
                  Install Web statistics in Settings → Services
                </Link>
              ) : (
                "Install Web statistics in Settings → Services"
              )}
            </p>
          ) : report.kind === "loading" || report.kind === "idle" ? (
            <div className="h-[900px] bg-dark-700/40 rounded animate-pulse" />
          ) : report.kind === "none" ? (
            <div className="flex items-center gap-3 flex-wrap">
              <p className="text-sm text-dark-300">Statistics are being prepared</p>
              <button onClick={refresh} disabled={refreshing || stats.running} className={btn}>
                {refreshing || stats.running ? "Computing..." : "Refresh"}
              </button>
            </div>
          ) : report.kind === "error" ? (
            <p className="text-xs text-danger-400">{report.text}</p>
          ) : fullScreen ? (
            // One live copy of the report at a time: the overlay holds it.
            <div className="h-[900px] rounded border border-dark-600 flex items-center justify-center text-xs text-dark-300">
              Shown in full screen
            </div>
          ) : (
            <ReportFrame html={report.html} className="w-full h-[900px] rounded border border-dark-600 bg-white" />
          )}
          {installed && (
            <p className="text-[10px]">
              <DbIpAttribution />
            </p>
          )}
        </div>
      )}

      {fullScreen && html && createPortal(
        <div
          className="fixed inset-0 z-50 flex flex-col bg-dark-900"
          role="dialog"
          aria-modal="true"
          aria-label={`Web statistics of ${domain}`}
        >
          <div className="px-4 py-2 flex items-center justify-between gap-3 border-b border-dark-600 bg-dark-800">
            <span className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest truncate">
              Web statistics <span className="normal-case tracking-normal text-dark-100">{domain}</span>
            </span>
            <div className="flex items-center gap-3 shrink-0">
              <DbIpAttribution className="text-[10px]" />
              <button ref={closeRef} onClick={() => setFullScreen(false)} className={btn}>
                Close
              </button>
            </div>
          </div>
          <ReportFrame html={html} className="flex-1 w-full bg-white" />
        </div>,
        document.body,
      )}
    </div>
  );
}
