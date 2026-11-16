import { useState, useEffect, useCallback } from "react";
import { api, ApiError } from "../api";
import { useServer } from "../context/ServerContext";
import { formatSize } from "../utils/format";
import ConfirmDialog from "./ConfirmDialog";

// ── Shapes (08-stats-web-contrats.md A-1, A-2, A-4, B-2) ─────────────────────

/** `GET /api/web-stats/status` relays the agent's A-1 answer. */
export interface WebStatsStatus {
  supported: boolean;
  unsupported_reason: string | null;
  installed: boolean;
  version: string | null;
  geoip: { present: boolean; updated_at: string | null; error: string | null } | null;
  /** Domain being computed right now, or null. */
  running: string | null;
  sites: number;
  data_bytes: number;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/** "2026-11-01T03:00:00Z" -> "2026-11-01" (the contract's wording). */
const isoDay = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : null);

const BUSY_TEXT = "An install, uninstall, purge or statistics run is in progress on this server. Try again in a few minutes.";

/** Attribution required by the DB-IP Country Lite licence (CC BY 4.0). */
export function DbIpAttribution({ className = "" }: { className?: string }) {
  return (
    <a
      href="https://db-ip.com"
      target="_blank"
      rel="noopener noreferrer"
      className={`text-accent-400 hover:text-accent-300 ${className}`}
    >
      IP Geolocation by DB-IP
    </a>
  );
}

/**
 * GoAccess in Settings -> Services: state and version, GeoIP database,
 * statistics data on disk, install, uninstall (data kept) and purge.
 */
export default function WebStatsServerCard() {
  const { activeServerId } = useServer();
  const [status, setStatus] = useState<WebStatsStatus | null>(null);
  const [statusError, setStatusError] = useState("");
  const [loading, setLoading] = useState(true);
  const [installing, setInstalling] = useState(false);
  const [uninstalling, setUninstalling] = useState(false);
  const [purging, setPurging] = useState(false);
  const [confirm, setConfirm] = useState<"uninstall" | "purge" | null>(null);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [msg, setMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const cancelConfirm = useCallback(() => setConfirm(null), []);

  const refresh = useCallback(async () => {
    if (!activeServerId) return;
    try {
      const s = await api.get<WebStatsStatus>(`/web-stats/status?server_id=${encodeURIComponent(activeServerId)}`);
      setStatus(s);
      setStatusError("");
    } catch (e) {
      setStatusError(errText(e, "Could not read the web statistics status"));
    } finally {
      setLoading(false);
    }
  }, [activeServerId]);

  useEffect(() => {
    setStatus(null);
    setMsg(null);
    setWarnings([]);
    setLoading(true);
    refresh();
  }, [refresh]);

  // While a run is in progress, follow it so "Running: x" goes away by itself.
  const runningDomain = status?.running ?? null;
  useEffect(() => {
    if (!runningDomain) return;
    const t = setInterval(refresh, 15000);
    return () => clearInterval(t);
  }, [runningDomain, refresh]);

  const doInstall = async () => {
    if (!activeServerId) return;
    setMsg(null);
    setWarnings([]);
    setInstalling(true);
    try {
      const r = await api.post<{ ok: boolean; warnings?: string[] }>("/web-stats/install", { server_id: activeServerId });
      setWarnings(r.warnings ?? []);
      setMsg({ text: "Web statistics installed. The first statistics run has started.", type: "success" });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setMsg({ text: BUSY_TEXT, type: "error" });
      } else if (e instanceof ApiError && e.status === 412) {
        setMsg({ text: errText(e, "Not supported on this server"), type: "error" });
      } else {
        setMsg({ text: errText(e, "Web statistics install failed"), type: "error" });
      }
    } finally {
      setInstalling(false);
      refresh();
    }
  };

  const doUninstall = async () => {
    if (!activeServerId) return;
    setConfirm(null);
    setMsg(null);
    setWarnings([]);
    setUninstalling(true);
    try {
      await api.post("/web-stats/uninstall", { server_id: activeServerId });
      setMsg({ text: "Web statistics uninstalled. Statistics data is kept.", type: "success" });
    } catch (e) {
      setMsg({ text: e instanceof ApiError && e.status === 409 ? BUSY_TEXT : errText(e, "Uninstall failed"), type: "error" });
    } finally {
      setUninstalling(false);
      refresh();
    }
  };

  const doPurge = async () => {
    if (!activeServerId) return;
    setConfirm(null);
    setMsg(null);
    setWarnings([]);
    setPurging(true);
    try {
      const r = await api.post<{ ok: boolean; removed?: number }>("/web-stats/purge", { server_id: activeServerId });
      const n = r.removed ?? 0;
      setMsg({ text: `Statistics data deleted (${n === 1 ? "1 site" : `${n} sites`})`, type: "success" });
    } catch (e) {
      setMsg({ text: e instanceof ApiError && e.status === 409 ? BUSY_TEXT : errText(e, "Could not delete the statistics data"), type: "error" });
    } finally {
      setPurging(false);
      refresh();
    }
  };

  const busy = installing || uninstalling || purging;
  const geoip = status?.geoip ?? null;
  const hasData = !!status && (status.sites > 0 || status.data_bytes > 0);

  return (
    <div className="border border-dark-500 bg-dark-900/50 p-4 space-y-3 h-full">
      {confirm === "uninstall" && (
        <ConfirmDialog
          label={"Uninstall Web statistics?\nHourly updates stop and GoAccess is removed. Statistics data is kept and comes back on a reinstall."}
          confirmLabel="Uninstall"
          tone="danger"
          onConfirm={doUninstall}
          onCancel={cancelConfirm}
        />
      )}
      {confirm === "purge" && (
        <ConfirmDialog
          label={"Delete statistics data?\nThis deletes the history of every site. It cannot be undone."}
          confirmLabel="Delete"
          tone="danger"
          onConfirm={doPurge}
          onCancel={cancelConfirm}
        />
      )}

      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium text-dark-50">Web statistics (GoAccess)</span>
            {status?.installed && status.version && <span className="text-[10px] text-dark-300">{status.version}</span>}
          </div>
          <p className="text-[10px] text-dark-300 mt-0.5">
            Visitors, pages, countries and robots for every site, from the nginx access logs. Updated every hour.
          </p>
        </div>
        <div className="shrink-0">
          {loading && !status ? (
            <span className="text-[10px] text-dark-300 uppercase tracking-wider">Checking...</span>
          ) : !status ? null : !status.supported ? (
            <span className="text-[10px] text-dark-300 uppercase tracking-wider">Not supported on this server</span>
          ) : status.installed && !installing ? (
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-dark-300 uppercase tracking-wider">Installed</span>
              <button
                onClick={() => setConfirm("uninstall")}
                disabled={busy}
                className="px-2.5 py-1 bg-danger-500/10 text-danger-400 border border-danger-500/20 rounded-lg text-[10px] font-medium hover:bg-danger-500/20 disabled:opacity-50"
              >
                {uninstalling ? "Removing..." : "Uninstall"}
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              {!installing && <span className="text-[10px] text-dark-300 uppercase tracking-wider">Not installed</span>}
              <button
                onClick={doInstall}
                disabled={busy || !activeServerId}
                className="px-3 py-1.5 bg-rust-500 text-white rounded-lg text-xs font-medium hover:bg-rust-600 disabled:opacity-50"
              >
                {installing ? "Installing..." : "Install"}
              </button>
            </div>
          )}
        </div>
      </div>

      {statusError && <p className="text-xs text-danger-400">{statusError}</p>}

      {status && !status.supported && status.unsupported_reason && (
        <p className="text-[10px] text-dark-300">{status.unsupported_reason}</p>
      )}

      {installing && (
        <p className="text-[11px] text-dark-300">
          Installing GoAccess and downloading the country database. This can take a few minutes.
        </p>
      )}

      {status?.supported && status.running && (
        <p className="text-[11px] text-dark-200">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-rust-400 animate-pulse mr-1.5 align-middle" />
          Running: <span className="font-mono">{status.running}</span>
        </p>
      )}

      {status?.supported && status.installed && !installing && (
        <div className="text-[11px] space-y-0.5">
          <p>
            <span className="text-dark-400 uppercase tracking-wider text-[10px] mr-2">GeoIP</span>
            {geoip?.error ? (
              <span className="text-warn-400">Country database: {geoip.error}</span>
            ) : geoip?.present ? (
              <span className="text-dark-100">
                Country database: {isoDay(geoip.updated_at) ? `updated ${isoDay(geoip.updated_at)}` : "present"}
              </span>
            ) : (
              <span className="text-dark-300">Country database: not downloaded yet</span>
            )}
          </p>
          <p className="text-[10px]">
            <DbIpAttribution />
          </p>
        </div>
      )}

      {status?.supported && (status.installed || hasData) && (
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <span className="text-[11px] text-dark-100">
            {status.sites === 1 ? "1 site" : `${status.sites} sites`}, {formatSize(status.data_bytes)} of statistics data
          </span>
          {hasData && (
            <button
              onClick={() => setConfirm("purge")}
              disabled={busy || !!status.running}
              title={status.running ? "Wait for the current statistics run to finish" : undefined}
              className="px-2.5 py-1 bg-danger-500/10 text-danger-400 border border-danger-500/20 rounded-lg text-[10px] font-medium hover:bg-danger-500/20 disabled:opacity-50"
            >
              {purging ? "Deleting..." : "Delete statistics data"}
            </button>
          )}
        </div>
      )}

      {warnings.length > 0 && (
        <ul className="space-y-0.5">
          {warnings.map((w) => (
            <li key={w} className="text-[11px] text-warn-400">{w}</li>
          ))}
        </ul>
      )}

      {msg && (
        <p className={`text-xs ${msg.type === "success" ? "text-rust-400" : "text-danger-400"}`}>{msg.text}</p>
      )}
    </div>
  );
}
