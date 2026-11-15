import { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { api, ApiError } from "../api";
import { useServer } from "../context/ServerContext";
import { formatSize, formatDate } from "../utils/format";
import ConfirmDialog from "./ConfirmDialog";

// ── Shapes (06-clamav-contrats.md A-1, A-6, B-R) ─────────────────────────────

export interface AvSchedule {
  enabled: boolean;
  hour: number;
  interval_days: number;
  last_run_at: string | null;
  next_run_at: string | null;
  /** Not in the contract: shown when the backend reports the server's zone, "UTC" otherwise. */
  timezone?: string | null;
}

export interface AvStatus {
  supported: boolean;
  unsupported_reason: string | null;
  installed: boolean;
  running: boolean;
  responding: boolean;
  version: string | null;
  signatures: { version: number; updated_at: string | null } | null;
  memory_bytes: number | null;
  total_ram_bytes: number | null;
  mail: { enabled: boolean; rspamd_installed: boolean; mail_installed: boolean } | null;
  install_job: string | null;
  /** Added by the backend (B-R `/status`). */
  schedule?: AvSchedule | null;
}

/** `GET /antivirus/jobs/{job_id}` (the agent's `migration_jobs::get`). */
export interface AvJob {
  job_id: string;
  kind: string;
  key: string;
  state: "running" | "done" | "failed";
  phase: string;
  bytes_done: number;
  bytes_total: number;
  message: string;
  warnings: string[];
  report: unknown;
  error: string | null;
  updated_at: number;
}

const GB = 1024 * 1024 * 1024;
/** Below this the agent refuses the install (A-2). */
export const AV_MIN_RAM_BYTES = 2 * GB;
/** Below this the install is allowed with a warning (A-2). */
export const AV_WARN_RAM_BYTES = 4 * GB;

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/**
 * `GET /antivirus/status?server_id=` for the server selected in the header.
 * Admin only (B-R). Skips the call while no server is selected and re-reads
 * when the selection changes.
 */
export function useAntivirusStatus(enabled = true) {
  const { activeServerId } = useServer();
  const [status, setStatus] = useState<AvStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async (): Promise<AvStatus | null> => {
    if (!activeServerId) {
      setLoading(false);
      return null;
    }
    try {
      const s = await api.get<AvStatus>(`/antivirus/status?server_id=${encodeURIComponent(activeServerId)}`);
      setStatus(s);
      setError("");
      return s;
    } catch (e) {
      setError(errText(e, "Could not read the antivirus status"));
      return null;
    } finally {
      setLoading(false);
    }
  }, [activeServerId]);

  useEffect(() => {
    if (!enabled) return;
    setStatus(null);
    setLoading(true);
    refresh();
  }, [enabled, refresh]);

  return { status, error, loading, refresh, serverId: activeServerId };
}

// ── Settings -> Services card ────────────────────────────────────────────────

/**
 * ClamAV in Settings -> Services: state, version, signatures, memory, install
 * (RAM warning first, progress polled from the job every 3 s) and uninstall.
 */
export default function ClamavCard() {
  const { status, error: statusError, loading, refresh, serverId } = useAntivirusStatus();
  const [jobId, setJobId] = useState<string | null>(null);
  const [job, setJob] = useState<AvJob | null>(null);
  const [starting, setStarting] = useState(false);
  const [uninstalling, setUninstalling] = useState(false);
  const [confirm, setConfirm] = useState<"install" | "uninstall" | null>(null);
  const [msg, setMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;

  // An install started elsewhere (another tab, before a reload) is resumed.
  useEffect(() => {
    if (status?.install_job && !jobId) setJobId(status.install_job);
  }, [status?.install_job, jobId]);

  // Forget the job when the operator switches server.
  useEffect(() => {
    setJobId(null);
    setJob(null);
    setMsg(null);
  }, [serverId]);

  useEffect(() => {
    if (!jobId || !serverId) return;
    let stopped = false;
    const poll = async () => {
      try {
        const j = await api.get<AvJob>(
          `/antivirus/jobs/${encodeURIComponent(jobId)}?server_id=${encodeURIComponent(serverId)}`,
        );
        if (stopped) return;
        setJob(j);
        if (j.state === "done") {
          stopped = true;
          window.clearInterval(t);
          setJobId(null);
          setMsg({ text: "ClamAV installed", type: "success" });
          refreshRef.current();
        } else if (j.state === "failed") {
          stopped = true;
          window.clearInterval(t);
          setJobId(null);
          setMsg({ text: j.error || "ClamAV install failed", type: "error" });
          refreshRef.current();
        }
      } catch (e) {
        if (stopped) return;
        if (e instanceof ApiError && e.status === 404) {
          // The agent restarted and forgot the job: the server is the authority.
          stopped = true;
          window.clearInterval(t);
          setJobId(null);
          setJob(null);
          const s = await refreshRef.current();
          if (!s?.installed) {
            setMsg({ text: "The install job was lost (agent restarted). Check the status and retry.", type: "error" });
          }
        }
        // Other errors (agent briefly unreachable): keep polling.
      }
    };
    const t = window.setInterval(poll, 3000);
    poll();
    return () => {
      stopped = true;
      window.clearInterval(t);
    };
  }, [jobId, serverId]);

  const lowRam = status?.total_ram_bytes != null && status.total_ram_bytes < AV_WARN_RAM_BYTES;
  const tooLittleRam = status?.total_ram_bytes != null && status.total_ram_bytes < AV_MIN_RAM_BYTES;

  const startInstall = async () => {
    if (!serverId) return;
    setConfirm(null);
    setMsg(null);
    setJob(null);
    setStarting(true);
    try {
      const r = await api.post<{ job_id: string }>("/antivirus/install", { server_id: serverId });
      setJobId(r.job_id);
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        // An install is already running: follow it.
        const s = await refresh();
        if (s?.install_job) {
          setJobId(s.install_job);
          return;
        }
      }
      setMsg({ text: errText(e, "Could not start the install"), type: "error" });
    } finally {
      setStarting(false);
    }
  };

  const onInstallClick = () => {
    if (lowRam) setConfirm("install");
    else startInstall();
  };

  const doUninstall = async () => {
    if (!serverId) return;
    setConfirm(null);
    setMsg(null);
    setUninstalling(true);
    try {
      await api.post("/antivirus/uninstall", { server_id: serverId });
      setMsg({ text: "ClamAV uninstalled", type: "success" });
      refresh();
    } catch (e) {
      setMsg({ text: errText(e, "Uninstall failed"), type: "error" });
    } finally {
      setUninstalling(false);
    }
  };

  const installing = starting || jobId !== null;
  const pct = job && job.bytes_total > 0 ? Math.min(100, Math.round((job.bytes_done / job.bytes_total) * 100)) : null;

  return (
    <div className="border border-dark-500 bg-dark-900/50 p-4 space-y-3">
      {confirm === "install" && (
        <ConfirmDialog
          label={`This server has ${status?.total_ram_bytes ? formatSize(status.total_ram_bytes) : "less than 4 GB"} of RAM. ClamAV keeps its signature database in memory and uses about 1.5 GB. Install anyway?`}
          confirmLabel="Install"
          tone="warn"
          onConfirm={startInstall}
          onCancel={() => setConfirm(null)}
        />
      )}
      {confirm === "uninstall" && (
        <ConfirmDialog
          label={"Uninstall ClamAV?\nMail antivirus is turned off first and scheduled scans stop. Quarantined files are kept."}
          confirmLabel="Uninstall"
          tone="danger"
          onConfirm={doUninstall}
          onCancel={() => setConfirm(null)}
        />
      )}

      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-dark-50">ClamAV</span>
            {status?.version && <span className="text-[10px] text-dark-300">{status.version}</span>}
            {status?.installed && (
              <span
                className={`w-2 h-2 rounded-full ${status.responding ? "bg-rust-400" : "bg-warn-400"}`}
                title={status.responding ? "Running" : status.running ? "Running but not responding" : "Installed but not running"}
              />
            )}
          </div>
          <p className="text-[10px] text-dark-300 mt-0.5">
            Antivirus for mail (through Rspamd) and for site files (scheduled and on-demand scans)
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
                disabled={uninstalling}
                className="px-2.5 py-1 bg-danger-500/10 text-danger-400 border border-danger-500/20 rounded-lg text-[10px] font-medium hover:bg-danger-500/20 disabled:opacity-50"
              >
                {uninstalling ? "Removing..." : "Uninstall"}
              </button>
            </div>
          ) : (
            <button
              onClick={onInstallClick}
              disabled={installing || tooLittleRam || !serverId}
              title={tooLittleRam ? "ClamAV needs at least 2 GB of RAM" : undefined}
              className="px-3 py-1.5 bg-rust-500 text-white rounded-lg text-xs font-medium hover:bg-rust-600 disabled:opacity-50"
            >
              {installing ? "Installing..." : "Install"}
            </button>
          )}
        </div>
      </div>

      {statusError && <p className="text-xs text-danger-400">{statusError}</p>}

      {status && !status.supported && status.unsupported_reason && (
        <p className="text-[10px] text-dark-300">{status.unsupported_reason}</p>
      )}

      {status?.supported && !status.installed && !installing && (
        tooLittleRam ? (
          <p className="text-xs text-danger-400">ClamAV needs at least 2 GB of RAM.</p>
        ) : lowRam ? (
          <p className="text-xs text-warn-400">Less than 4 GB of RAM: ClamAV uses about 1.5 GB.</p>
        ) : null
      )}

      {status?.installed && !installing && (
        <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1 text-[11px]">
          <div>
            <dt className="text-dark-400 uppercase tracking-wider text-[10px]">State</dt>
            <dd className={status.responding ? "text-rust-400" : "text-warn-400"}>
              {status.responding ? "Responding" : status.running ? "Not responding" : "Stopped"}
            </dd>
          </div>
          <div>
            <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Signatures</dt>
            <dd className="text-dark-100 font-mono">{status.signatures ? status.signatures.version : "-"}</dd>
          </div>
          <div>
            <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Updated</dt>
            <dd className="text-dark-100">
              {status.signatures?.updated_at ? formatDate(status.signatures.updated_at) : "-"}
            </dd>
          </div>
          <div>
            <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Memory</dt>
            <dd className="text-dark-100 font-mono">{status.memory_bytes != null ? formatSize(status.memory_bytes) : "-"}</dd>
          </div>
        </dl>
      )}

      {installing && (
        <div className="bg-dark-950 border border-dark-600 p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className="text-dark-100">
              Installing ClamAV{job?.phase ? `: ${job.phase}` : "..."}
            </span>
            {pct !== null && <span className="text-dark-300 font-mono">{pct}%</span>}
          </div>
          {pct !== null && (
            <div className="h-1.5 bg-dark-700 rounded-full overflow-hidden">
              <div className="h-full bg-rust-500 transition-all" style={{ width: `${pct}%` }} />
            </div>
          )}
          {job?.message && <p className="text-[11px] text-dark-300 font-mono break-words">{job.message}</p>}
          <p className="text-[10px] text-dark-400">
            The signature download can take up to 15 minutes. It runs on the server, so leaving this page will not stop it.
          </p>
        </div>
      )}

      {job && job.warnings.length > 0 && (
        <ul className="space-y-0.5">
          {job.warnings.map((w) => (
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

// ── Mail -> Spam Filter: antivirus toggle ────────────────────────────────────

/**
 * The "Antivirus" switch of the Spam Filter card. Needs ClamAV and Rspamd; the
 * button is disabled with the reason otherwise. `rspamdKey` changes whenever
 * Rspamd is installed or toggled on the page, so the state is read again.
 */
export function MailAntivirusToggle({ rspamdKey }: { rspamdKey?: string }) {
  const { status, error, refresh, serverId } = useAntivirusStatus();
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");

  // Re-read after an Rspamd change on the page (the first value is the mount,
  // already covered by the hook).
  const lastKey = useRef(rspamdKey);
  useEffect(() => {
    if (lastKey.current === rspamdKey) return;
    lastKey.current = rspamdKey;
    refresh();
  }, [rspamdKey, refresh]);

  if (!status) {
    return error ? <p className="text-[11px] text-danger-400 mt-3">{error}</p> : null;
  }

  const enabled = status.mail?.enabled ?? false;
  const reason = !status.supported
    ? "ClamAV is not supported on this server."
    : !status.installed
      ? "Needs ClamAV. Install it in Settings > Services."
      : !status.mail?.rspamd_installed
        ? "Needs Rspamd. Install it above."
        : !enabled && !status.responding
          ? "ClamAV is not responding."
          : "";

  const toggle = async () => {
    if (!serverId) return;
    setBusy(true);
    setActionError("");
    try {
      await api.post("/antivirus/mail", { server_id: serverId, enable: !enabled });
      await refresh();
    } catch (e) {
      setActionError(errText(e, "Failed"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="mt-3 pt-3 border-t border-dark-600 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs text-dark-200">Antivirus</span>
        <span className={`text-[10px] uppercase tracking-wider ${enabled ? "text-rust-400" : "text-dark-400"}`}>
          {enabled ? "On" : "Off"}
        </span>
      </div>
      {status.installed && !status.responding && enabled && (
        <div className="px-2.5 py-1.5 bg-warn-500/10 border border-warn-500/30 rounded text-[11px] text-warn-400">
          ClamAV is not responding: mail is delivered without virus scanning
        </div>
      )}
      <button
        onClick={toggle}
        disabled={busy || reason !== "" || !serverId}
        title={reason || undefined}
        className={`w-full px-3 py-1.5 rounded text-xs font-medium transition-colors disabled:opacity-50 ${enabled ? "bg-dark-700 text-dark-100 hover:bg-dark-600" : "bg-rust-500 text-white hover:bg-rust-600"}`}
      >
        {busy ? "Working..." : enabled ? "Disable antivirus" : "Enable antivirus"}
      </button>
      {reason && (
        <p className="text-[11px] text-dark-300">
          {reason}
          {!status.installed && status.supported && (
            <>
              {" "}
              <Link to="/settings?tab=services" className="text-accent-400 hover:text-accent-300">Open Services</Link>
            </>
          )}
        </p>
      )}
      {actionError && <p className="text-[11px] text-danger-400">{actionError}</p>}
    </div>
  );
}
