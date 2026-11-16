import { useState, useEffect, useCallback } from "react";
import { api, ApiError } from "../api";
import { useServer } from "../context/ServerContext";
import ConfirmDialog from "./ConfirmDialog";

// ── Shapes (07-ftp-quotas-contrats.md A-1, A-2, B-2) ─────────────────────────

/** `GET /api/ftp/status` relays the agent's A-1 answer. Everything below
 *  `running` is null while vsftpd is not installed. */
export interface FtpStatus {
  supported: boolean;
  unsupported_reason: string | null;
  installed: boolean;
  running: boolean;
  cert: { kind: "letsencrypt" | "self_signed"; subject: string | null; expires_at: string | null } | null;
  ports: { control: number; passive_min: number; passive_max: number } | null;
  firewall: "open" | "closed" | "none" | null;
  fail2ban_jail: boolean | null;
  users: number | null;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/** "2027-02-10T00:00:00Z" -> "2027-02-10" (the contract's wording). */
const isoDay = (iso: string | null | undefined) => (iso ? iso.slice(0, 10) : null);

/**
 * `GET /api/ftp/status` (admin only). `serverId` undefined = the header's
 * selected server; null = the backend's default (the local server).
 */
export function useFtpStatus(enabled: boolean, serverId?: string | null) {
  const [status, setStatus] = useState<FtpStatus | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(enabled);

  const refresh = useCallback(async (): Promise<FtpStatus | null> => {
    try {
      const q = serverId ? `?server_id=${encodeURIComponent(serverId)}` : "";
      const s = await api.get<FtpStatus>(`/ftp/status${q}`);
      setStatus(s);
      setError("");
      return s;
    } catch (e) {
      setError(errText(e, "Could not read the FTP server status"));
      return null;
    } finally {
      setLoading(false);
    }
  }, [serverId]);

  useEffect(() => {
    if (!enabled) return;
    setStatus(null);
    setLoading(true);
    refresh();
  }, [enabled, refresh]);

  return { status, error, loading, refresh };
}

// ── Settings -> Services card ────────────────────────────────────────────────

/**
 * vsftpd in Settings -> Services: state, certificate, ports, firewall and
 * fail2ban, install (one synchronous call, up to 5 minutes) and uninstall.
 */
export default function FtpServerCard() {
  const { activeServerId } = useServer();
  const { status, error: statusError, loading, refresh } = useFtpStatus(!!activeServerId, activeServerId);
  const [installing, setInstalling] = useState(false);
  const [uninstalling, setUninstalling] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [msg, setMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const cancelConfirm = useCallback(() => setConfirmUninstall(false), []);

  useEffect(() => {
    setMsg(null);
    setWarnings([]);
  }, [activeServerId]);

  const doInstall = async () => {
    if (!activeServerId) return;
    setMsg(null);
    setWarnings([]);
    setInstalling(true);
    try {
      const r = await api.post<{ ok: boolean; warnings?: string[] }>("/ftp/install", { server_id: activeServerId });
      setWarnings(r.warnings ?? []);
      setMsg({ text: "FTP server installed", type: "success" });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setMsg({ text: "An install or uninstall is already running on this server. Try again in a few minutes.", type: "error" });
      } else if (e instanceof ApiError && e.status === 412) {
        setMsg({ text: errText(e, "Not supported on this server"), type: "error" });
      } else {
        setMsg({ text: errText(e, "FTP server install failed"), type: "error" });
      }
    } finally {
      setInstalling(false);
      refresh();
    }
  };

  const doUninstall = async () => {
    if (!activeServerId) return;
    setConfirmUninstall(false);
    setMsg(null);
    setWarnings([]);
    setUninstalling(true);
    try {
      await api.post("/ftp/uninstall", { server_id: activeServerId });
      setMsg({ text: "FTP server uninstalled", type: "success" });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setMsg({ text: "An install or uninstall is already running on this server. Try again in a few minutes.", type: "error" });
      } else {
        setMsg({ text: errText(e, "Uninstall failed"), type: "error" });
      }
    } finally {
      setUninstalling(false);
      refresh();
    }
  };

  const busy = installing || uninstalling;
  const cert = status?.cert ?? null;
  const ports = status?.ports ?? null;

  return (
    <div className="border border-dark-500 bg-dark-900/50 p-4 space-y-3">
      {confirmUninstall && (
        <ConfirmDialog
          label={"Uninstall the FTP server?\nOpen FTP sessions are cut and the FTP ports are closed. The FTP setting of each site is kept and comes back on a reinstall."}
          confirmLabel="Uninstall"
          tone="danger"
          onConfirm={doUninstall}
          onCancel={cancelConfirm}
        />
      )}

      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium text-dark-50">FTP server (vsftpd)</span>
            {status?.installed && (
              <span
                className={`w-2 h-2 rounded-full ${status.running ? "bg-rust-400" : "bg-warn-400"}`}
                title={status.running ? "Running" : "Stopped"}
              />
            )}
          </div>
          <p className="text-[10px] text-dark-300 mt-0.5">
            FTPS access to site files, with the same account and password as SFTP. Plain FTP is refused.
          </p>
        </div>
        <div className="shrink-0">
          {loading && !status ? (
            <span className="text-[10px] text-dark-300 uppercase tracking-wider">Checking...</span>
          ) : !status ? null : !status.supported ? (
            <span className="text-[10px] text-dark-300 uppercase tracking-wider">Not supported on this server</span>
          ) : status.installed && !installing ? (
            <div className="flex items-center gap-2">
              <span className={`text-[10px] uppercase tracking-wider ${status.running ? "text-dark-300" : "text-warn-400"}`}>
                {status.running ? "Running" : "Stopped"}
              </span>
              <button
                onClick={() => setConfirmUninstall(true)}
                disabled={busy}
                className="px-2.5 py-1 bg-danger-500/10 text-danger-400 border border-danger-500/20 rounded-lg text-[10px] font-medium hover:bg-danger-500/20 disabled:opacity-50"
              >
                {uninstalling ? "Removing..." : "Uninstall"}
              </button>
            </div>
          ) : (
            <button
              onClick={doInstall}
              disabled={busy || !activeServerId}
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

      {installing && (
        <p className="text-[11px] text-dark-300">
          Installing vsftpd, writing its configuration and opening the firewall. This can take a few minutes.
        </p>
      )}

      {status?.installed && !installing && (
        <>
          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-x-4 gap-y-1 text-[11px]">
            <div>
              <dt className="text-dark-400 uppercase tracking-wider text-[10px]">State</dt>
              <dd className={status.running ? "text-rust-400" : "text-warn-400"}>{status.running ? "Running" : "Stopped"}</dd>
            </div>
            <div>
              <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Ports</dt>
              <dd className="text-dark-100 font-mono">
                {ports ? `${ports.control}, passive ${ports.passive_min}-${ports.passive_max}` : "-"}
              </dd>
            </div>
            <div>
              <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Firewall</dt>
              <dd className={status.firewall === "closed" ? "text-warn-400" : "text-dark-100"}>
                {status.firewall === "open"
                  ? "Ports open"
                  : status.firewall === "closed"
                    ? "Ports closed"
                    : status.firewall === "none"
                      ? "No managed firewall"
                      : "-"}
              </dd>
            </div>
            <div>
              <dt className="text-dark-400 uppercase tracking-wider text-[10px]">Fail2ban</dt>
              <dd className="text-dark-100">
                {status.fail2ban_jail == null ? "-" : status.fail2ban_jail ? "Jail active" : "No jail"}
              </dd>
            </div>
          </dl>
          <div className="text-[11px]">
            <span className="text-dark-400 uppercase tracking-wider text-[10px] mr-2">Certificate</span>
            {!cert ? (
              <span className="text-dark-300">-</span>
            ) : cert.kind === "letsencrypt" ? (
              <span className="text-dark-100">
                Let's Encrypt{cert.subject ? ` (${cert.subject})` : ""}
                {isoDay(cert.expires_at) ? `, expires ${isoDay(cert.expires_at)}` : ""}
              </span>
            ) : (
              <span className="text-warn-400">Self-signed certificate: FTP clients will ask to trust it</span>
            )}
          </div>
          {status.users != null && (
            <p className="text-[10px] text-dark-300">
              {status.users === 1 ? "1 site account allowed" : `${status.users} site accounts allowed`} to log in over FTP
            </p>
          )}
        </>
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
