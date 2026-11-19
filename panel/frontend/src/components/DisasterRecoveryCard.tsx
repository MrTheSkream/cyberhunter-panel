import { useState, useEffect, useCallback, useRef } from "react";
import { createPortal } from "react-dom";
import { useLocation } from "react-router-dom";
import { api, ApiError } from "../api";
import { formatDate, formatSize } from "../utils/format";
import ConfirmDialog from "./ConfirmDialog";

/**
 * Disaster recovery: encrypted (age) off-site copies of the panel itself
 * (database dump and /etc/dockpanel), pushed to Backup Orchestrator
 * destinations. Rendered on the Updates tab of Telemetry, under Snapshots,
 * and deep-linked from the Backup Orchestrator as #disaster-recovery.
 *
 * The recovery identity (private key) is returned by the server exactly once,
 * at enrolment or rotation. It lives only in React state while the modal is
 * open and is cleared on close: never persisted, logged, put in the URL or
 * sent back to the server.
 */

type DrRunStatus = "running" | "success" | "partial" | "failed";

interface DrSettings {
  enabled: boolean;
  schedule: string;
  destination_ids: string[];
  remote_retention: number;
  enabled_at: string | null;
  last_run_at: string | null;
  last_status: DrRunStatus | null;
  last_error: string | null;
  updated_at: string;
}

interface DrRecipient {
  id: string;
  fingerprint: string;
  public_key: string;
  created_at: string;
  created_by: string | null;
}

interface DrRetiredRecipient extends DrRecipient {
  retired_at: string;
}

interface DrDestination {
  id: string;
  name: string;
  dtype: "s3" | "sftp";
}

interface DrRemoteSnapshot {
  id: string;
  snapshot_id: string | null;
  destination_id: string | null;
  destination_name: string | null;
  status: "uploaded" | "failed";
  error: string | null;
  remote_key: string | null;
  filename: string;
  size_bytes: number;
  sha256: string;
  recipient_fingerprint: string;
  from_version: string;
  created_at: string;
  uploaded_at: string | null;
  deleted_at: string | null;
}

interface DrStatus {
  install_id: string | null;
  settings: DrSettings;
  recipient: DrRecipient | null;
  retired_recipients: DrRetiredRecipient[];
  destinations: DrDestination[];
  remote_snapshots: DrRemoteSnapshot[];
  last_success_at: string | null;
  stale: boolean;
  running: boolean;
}

interface DrEnrolResponse {
  recipient: DrRecipient;
  identity: string;
  previous_fingerprint: string | null;
}

interface IssuedKey {
  identity: string;
  fingerprint: string;
  previousFingerprint: string | null;
  rotated: boolean;
}

const DEFAULT_SCHEDULE = "30 3 * * *";
const POLL_MS = 5000;
const ANCHOR = "#disaster-recovery";

function shortFingerprint(fp: string, n = 16): string {
  return fp.length > n ? `${fp.slice(0, n)}...` : fp;
}

/** First 8 characters of the fingerprint, without any "algo:" prefix. */
function keyFileName(fp: string): string {
  const bare = fp.replace(/^[^:]*:/, "").replace(/[^A-Za-z0-9]/g, "");
  return `cyberhunter-recovery-key-${bare.slice(0, 8)}.txt`;
}

export default function DisasterRecoveryCard() {
  const location = useLocation();
  const [status, setStatus] = useState<DrStatus | null>(null);
  const [forbidden, setForbidden] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [message, setMessage] = useState({ text: "", type: "" });

  // Configuration form. Synced from the server unless the operator is editing.
  const [enabled, setEnabled] = useState(false);
  const [schedule, setSchedule] = useState(DEFAULT_SCHEDULE);
  const [destIds, setDestIds] = useState<string[]>([]);
  const [retention, setRetention] = useState(14);
  const [dirty, setDirty] = useState(false);
  const dirtyRef = useRef(false);
  dirtyRef.current = dirty;

  const [saving, setSaving] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [rotateConfirm, setRotateConfirm] = useState(false);
  const [starting, setStarting] = useState(false);
  const [awaitingRun, setAwaitingRun] = useState(false);

  // One-time display of the recovery identity.
  const [issued, setIssued] = useState<IssuedKey | null>(null);
  const [stored, setStored] = useState(false);
  const [copied, setCopied] = useState(false);

  const scrolledRef = useRef(false);

  const flash = (text: string, type: "success" | "error") => {
    setMessage({ text, type });
    setTimeout(() => setMessage({ text: "", type: "" }), 6000);
  };

  const applyStatus = useCallback((data: DrStatus, force = false) => {
    setStatus(data);
    if (force || !dirtyRef.current) {
      setEnabled(data.settings.enabled);
      setSchedule(data.settings.schedule || DEFAULT_SCHEDULE);
      setDestIds(data.settings.destination_ids || []);
      setRetention(data.settings.remote_retention || 14);
      setDirty(false);
    }
  }, []);

  const load = useCallback(async () => {
    try {
      const data = await api.get<DrStatus>("/dr");
      applyStatus(data);
      setLoadError("");
      if (!data.running) setAwaitingRun(false);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 403) {
        setForbidden(true);
        return;
      }
      setLoadError(e instanceof Error ? e.message : "Could not load disaster recovery status");
    }
  }, [applyStatus]);

  useEffect(() => {
    void load();
  }, [load]);

  // Poll while a run is in progress (or was just started) until it finishes.
  const polling = !!status?.running || awaitingRun;
  useEffect(() => {
    if (!polling) return;
    const id = window.setInterval(() => void load(), POLL_MS);
    return () => window.clearInterval(id);
  }, [polling, load]);

  // Deep link from the Backup Orchestrator: scroll once the card has content.
  useEffect(() => {
    if (scrolledRef.current || !status || location.hash !== ANCHOR) return;
    scrolledRef.current = true;
    document.getElementById(ANCHOR.slice(1))?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [status, location.hash]);

  const edit = <T,>(setter: (v: T) => void) => (v: T) => {
    setter(v);
    setDirty(true);
  };

  const save = async () => {
    setSaving(true);
    try {
      const data = await api.put<DrStatus>("/dr/settings", {
        enabled,
        schedule: schedule.trim(),
        destination_ids: destIds,
        remote_retention: retention,
      });
      applyStatus(data, true);
      flash("Disaster recovery settings saved.", "success");
    } catch (e: unknown) {
      flash(e instanceof Error ? e.message : "Could not save the settings", "error");
    } finally {
      setSaving(false);
    }
  };

  const enrol = async (rotate: boolean) => {
    setRotateConfirm(false);
    setEnrolling(true);
    try {
      const data = await api.post<DrEnrolResponse>("/dr/recipient", { rotate });
      setStored(false);
      setCopied(false);
      setIssued({
        identity: data.identity,
        fingerprint: data.recipient.fingerprint,
        previousFingerprint: data.previous_fingerprint,
        rotated: rotate,
      });
    } catch (e: unknown) {
      flash(e instanceof Error ? e.message : "Could not create the recovery key", "error");
    } finally {
      setEnrolling(false);
    }
  };

  const cancelRotate = useCallback(() => setRotateConfirm(false), []);

  const downloadKey = () => {
    if (!issued) return;
    const blob = new Blob([issued.identity.endsWith("\n") ? issued.identity : `${issued.identity}\n`], {
      type: "text/plain",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = keyFileName(issued.fingerprint);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
  };

  const copyKey = async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.identity);
      setCopied(true);
    } catch {
      flash("Could not copy to the clipboard. Use Download instead.", "error");
    }
  };

  const closeIssued = () => {
    if (!stored) return;
    const wasRotation = issued?.rotated;
    const prev = issued?.previousFingerprint;
    setIssued(null);
    setStored(false);
    setCopied(false);
    if (wasRotation) {
      flash(
        `Recovery key rotated. Older remote snapshots still need the previous key${prev ? ` (${prev})` : ""}.`,
        "success",
      );
    } else {
      flash("Recovery key set up.", "success");
    }
    void load();
  };

  const runNow = async () => {
    setStarting(true);
    try {
      await api.post("/dr/run", {});
      setAwaitingRun(true);
      flash("Off-site snapshot started.", "success");
      void load();
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 409) setAwaitingRun(true);
      flash(e instanceof Error ? e.message : "Could not start the off-site snapshot", "error");
    } finally {
      setStarting(false);
    }
  };

  if (forbidden) return null;

  if (!status) {
    return (
      <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
        <h3 className="text-sm font-medium text-dark-100 mb-2">Disaster recovery</h3>
        <div className="text-xs text-dark-400">
          {loadError ? <span className="text-danger-400">{loadError}</span> : "Loading..."}
        </div>
      </div>
    );
  }

  const s = status.settings;
  const running = status.running || awaitingRun;
  const lastRunTime = s.last_run_at ? new Date(s.last_run_at).getTime() : null;
  const lastRunHasCopy =
    lastRunTime !== null &&
    status.remote_snapshots.some(
      r => r.status === "uploaded" && new Date(r.uploaded_at || r.created_at).getTime() >= lastRunTime,
    );
  const localOnly =
    !status.running &&
    (s.last_status === "failed" || (s.last_run_at !== null && s.last_status !== "running" && !lastRunHasCopy));

  const statusColor =
    s.last_status === "success"
      ? "text-rust-400"
      : s.last_status === "partial"
      ? "text-warn-400"
      : s.last_status === "failed"
      ? "text-danger-400"
      : "text-dark-300";

  const toggleDest = (id: string) => {
    setDestIds(prev => (prev.includes(id) ? prev.filter(d => d !== id) : [...prev, id]));
    setDirty(true);
  };

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-1">
        <h3 className="text-sm font-medium text-dark-100 flex items-center gap-2">
          Disaster recovery
          {localOnly && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-medium border bg-danger-500/10 text-danger-400 border-danger-500/20">
              Local only
            </span>
          )}
        </h3>
        <button
          onClick={runNow}
          disabled={starting || running || !status.recipient}
          className="px-3 py-1.5 bg-dark-700 text-dark-300 hover:bg-dark-600 hover:text-dark-100 border border-dark-500 rounded-lg text-xs transition-colors disabled:opacity-50"
        >
          {running ? "Running..." : starting ? "Starting..." : "Run off-site snapshot now"}
        </button>
      </div>
      <div className="text-xs text-dark-400 mb-3">
        An encrypted (age) archive of the panel (database and /etc/dockpanel) is sent off site. Binaries
        are not included: to restore, reinstall the same panel version first.
      </div>

      {message.text && (
        <div
          role="alert"
          className={`mb-3 px-3 py-2 rounded-lg text-xs border break-words ${
            message.type === "success"
              ? "bg-rust-500/10 text-rust-400 border-rust-500/20"
              : "bg-danger-500/10 text-danger-400 border-danger-500/20"
          }`}
        >
          {message.text}
        </div>
      )}

      {status.stale && (
        <div className="mb-3 px-3 py-2 rounded-lg text-xs border bg-warn-500/10 text-warn-400 border-warn-500/20">
          No off-site panel snapshot in the last 48 hours
          {status.last_success_at ? ` (last success ${formatDate(status.last_success_at)}).` : "."}
        </div>
      )}

      {/* Last run */}
      <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 mb-3 text-xs">
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
          <span className="text-dark-400">
            Last run:{" "}
            <span className="text-dark-200">{s.last_run_at ? formatDate(s.last_run_at) : "Never"}</span>
          </span>
          <span className="text-dark-400">
            Status: <span className={`font-medium ${statusColor}`}>{running ? "running" : s.last_status || "-"}</span>
          </span>
          {status.last_success_at && (
            <span className="text-dark-400">
              Last success: <span className="text-dark-200">{formatDate(status.last_success_at)}</span>
            </span>
          )}
        </div>
        {s.last_error && <div className="mt-1 text-danger-400 break-words">{s.last_error}</div>}
      </div>

      {/* Recovery key */}
      <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 mb-3 text-xs">
        <div className="text-dark-400 mb-1">Recovery key</div>
        {status.recipient ? (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="min-w-0">
              <div className="font-mono text-dark-200 break-all">{status.recipient.fingerprint}</div>
              <div className="text-dark-400 mt-0.5">
                Created {formatDate(status.recipient.created_at)}
                {status.recipient.created_by ? ` by ${status.recipient.created_by}` : ""}
              </div>
            </div>
            <button
              onClick={() => setRotateConfirm(true)}
              disabled={enrolling}
              className="px-2 py-1 bg-dark-700 hover:bg-dark-600 text-dark-300 border border-dark-600 rounded text-xs disabled:opacity-50"
            >
              {enrolling ? "..." : "Rotate recovery key"}
            </button>
          </div>
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-dark-300">
              No recovery key yet. Off-site snapshots are encrypted to this key, and only its holder can restore them.
            </span>
            <button
              onClick={() => void enrol(false)}
              disabled={enrolling}
              className="px-3 py-1.5 bg-rust-500 hover:bg-rust-600 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              {enrolling ? "Creating..." : "Set up recovery key"}
            </button>
          </div>
        )}
        {status.retired_recipients.length > 0 && (
          <div className="mt-2 text-dark-400">
            Previous keys (still needed for older remote snapshots):
            <ul className="mt-1 space-y-0.5">
              {status.retired_recipients.map(r => (
                <li key={r.id} className="font-mono break-all">
                  {r.fingerprint} <span className="font-sans">(retired {formatDate(r.retired_at)})</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
      {rotateConfirm && (
        <ConfirmDialog
          label={
            "Rotate the recovery key? New off-site snapshots will be encrypted to a new key, shown once.\n" +
            "Older remote snapshots still need the previous key: keep it."
          }
          confirmLabel="Rotate recovery key"
          tone="warn"
          onConfirm={() => void enrol(true)}
          onCancel={cancelRotate}
        />
      )}

      {/* Configuration */}
      <div className="space-y-3 mb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="text-sm text-dark-200">Off-site panel snapshots</div>
          <button
            type="button"
            role="switch"
            aria-checked={enabled}
            aria-label="Off-site panel snapshots"
            onClick={() => edit(setEnabled)(!enabled)}
            className={`shrink-0 relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
              enabled ? "bg-rust-500" : "bg-dark-600"
            }`}
          >
            <span
              className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                enabled ? "translate-x-6" : "translate-x-1"
              }`}
            />
          </button>
        </div>
        {enabled && !status.recipient && (
          <div className="text-xs text-warn-400">Set up a recovery key before enabling off-site snapshots.</div>
        )}

        <div>
          <label htmlFor="dr-schedule" className="block text-xs text-dark-300 mb-1">Schedule</label>
          <input
            id="dr-schedule"
            type="text"
            value={schedule}
            onChange={e => edit(setSchedule)(e.target.value)}
            placeholder={DEFAULT_SCHEDULE}
            className="w-full bg-dark-900 border border-dark-600 text-dark-100 text-sm rounded-lg px-3 py-1.5 font-mono"
          />
          <div className="text-xs text-dark-400 mt-1">Cron, UTC. Default: 30 3 * * * (03:30 every day)</div>
        </div>

        <div>
          <div className="text-xs text-dark-300 mb-1">Destinations</div>
          {status.destinations.length === 0 ? (
            <div className="text-xs text-dark-400">
              No eligible destination. Create an S3 or SFTP destination in the Backup Orchestrator first.
            </div>
          ) : (
            <div className="space-y-1">
              {status.destinations.map(d => (
                <label key={d.id} className="flex items-center gap-2 text-xs text-dark-300">
                  <input
                    type="checkbox"
                    checked={destIds.includes(d.id)}
                    onChange={() => toggleDest(d.id)}
                    className="rounded bg-dark-900 border-dark-600"
                  />
                  {d.name}
                  <span className="font-mono text-dark-400 uppercase">{d.dtype}</span>
                </label>
              ))}
            </div>
          )}
        </div>

        <div>
          <label htmlFor="dr-retention" className="block text-xs text-dark-300 mb-1">Keep remote copies</label>
          <input
            id="dr-retention"
            type="number"
            min={1}
            max={365}
            value={retention}
            onChange={e => edit(setRetention)(Math.max(1, Math.min(365, Number(e.target.value) || 1)))}
            className="w-28 bg-dark-900 border border-dark-600 text-dark-100 text-sm rounded-lg px-3 py-1.5 font-mono"
          />
        </div>

        <button
          onClick={save}
          disabled={saving}
          className="px-4 py-2 bg-rust-500 hover:bg-rust-600 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
        >
          {saving ? "Saving..." : "Save"}
        </button>
      </div>

      {/* Remote snapshots */}
      <div className="text-xs text-dark-400 mb-2">
        Remote snapshots <span className="font-normal">({status.remote_snapshots.length})</span>
      </div>
      {status.remote_snapshots.length === 0 ? (
        <div className="text-xs text-dark-400 py-3 text-center">No off-site panel snapshot yet.</div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-left text-dark-400 border-b border-dark-700">
                <th className="px-2 py-1.5 font-normal">File</th>
                <th className="px-2 py-1.5 font-normal">Destination</th>
                <th className="px-2 py-1.5 font-normal">Size</th>
                <th className="px-2 py-1.5 font-normal">Date</th>
                <th className="px-2 py-1.5 font-normal">Key</th>
                <th className="px-2 py-1.5 font-normal">Status</th>
              </tr>
            </thead>
            <tbody>
              {status.remote_snapshots.map(r => {
                const badge = r.deleted_at
                  ? { label: "Pruned", cls: "bg-dark-700 text-dark-400 border-dark-600" }
                  : r.status === "failed"
                  ? { label: "Upload failed", cls: "bg-danger-500/10 text-danger-400 border-danger-500/20" }
                  : { label: "Uploaded", cls: "bg-rust-500/10 text-rust-400 border-rust-500/20" };
                return (
                  <tr key={r.id} className="border-b border-dark-700/50">
                    <td className="px-2 py-1.5 font-mono text-dark-200 break-all" title={`sha256 ${r.sha256}`}>
                      {r.filename}
                    </td>
                    <td className="px-2 py-1.5 text-dark-300">{r.destination_name || "-"}</td>
                    <td className="px-2 py-1.5 text-dark-300 whitespace-nowrap">{formatSize(r.size_bytes)}</td>
                    <td className="px-2 py-1.5 text-dark-400 whitespace-nowrap">
                      {formatDate(r.uploaded_at || r.created_at)}
                    </td>
                    <td className="px-2 py-1.5 font-mono text-dark-400" title={r.recipient_fingerprint}>
                      {shortFingerprint(r.recipient_fingerprint)}
                    </td>
                    <td className="px-2 py-1.5">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap ${badge.cls}`}
                        title={r.status === "failed" ? r.error || undefined : undefined}
                      >
                        {badge.label}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {status.install_id && (
        <div className="text-[10px] text-dark-400 mt-3">
          Install ID: <span className="font-mono">{status.install_id}</span>
        </div>
      )}

      {/* One-time recovery key display. Deliberately not closable by Escape or
          a backdrop click: the operator must confirm the key is stored. */}
      {issued &&
        createPortal(
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 dp-modal-overlay">
            <div
              role="alertdialog"
              aria-modal="true"
              aria-label="Recovery key"
              className="bg-dark-800 rounded-lg shadow-xl p-6 w-full max-w-xl dp-modal"
            >
              <h3 className="text-sm font-medium text-dark-100 mb-2">Recovery key</h3>
              <p className="text-sm text-warn-400 mb-3">
                Store this recovery key offline now. It is shown only once and the panel cannot show it again.
              </p>
              {issued.rotated && (
                <p className="text-xs text-dark-300 mb-3">
                  Older remote snapshots still need the previous key
                  {issued.previousFingerprint ? (
                    <>
                      {" "}(<span className="font-mono break-all">{issued.previousFingerprint}</span>)
                    </>
                  ) : null}
                  . Do not discard it.
                </p>
              )}
              <div className="text-xs text-dark-400 mb-1">
                Fingerprint: <span className="font-mono text-dark-200 break-all">{issued.fingerprint}</span>
              </div>
              <textarea
                readOnly
                value={issued.identity}
                rows={5}
                spellCheck={false}
                autoComplete="off"
                onFocus={e => e.currentTarget.select()}
                className="w-full bg-dark-900 border border-dark-600 text-dark-100 text-xs rounded-lg px-3 py-2 font-mono mb-3 resize-none"
              />
              <div className="flex flex-wrap gap-2 mb-3">
                <button
                  onClick={downloadKey}
                  className="px-3 py-1.5 bg-dark-700 text-dark-200 hover:bg-dark-600 border border-dark-500 rounded-lg text-xs transition-colors"
                >
                  Download
                </button>
                <button
                  onClick={() => void copyKey()}
                  className="px-3 py-1.5 bg-dark-700 text-dark-200 hover:bg-dark-600 border border-dark-500 rounded-lg text-xs transition-colors"
                >
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <label className="flex items-center gap-2 text-xs text-dark-200 mb-4">
                <input
                  type="checkbox"
                  checked={stored}
                  onChange={e => setStored(e.target.checked)}
                  className="rounded bg-dark-900 border-dark-600"
                />
                I have stored the recovery key
              </label>
              <div className="flex justify-end">
                <button
                  onClick={closeIssued}
                  disabled={!stored}
                  className="px-4 py-2 bg-rust-500 hover:bg-rust-600 text-white text-xs font-bold uppercase tracking-wider rounded transition-colors disabled:opacity-50"
                >
                  Close
                </button>
              </div>
            </div>
          </div>,
          document.body,
        )}
    </div>
  );
}
