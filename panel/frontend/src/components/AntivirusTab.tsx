import { useState, useEffect, useCallback, useRef } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { formatSize, formatDate } from "../utils/format";
import ConfirmDialog from "./ConfirmDialog";
import { useAntivirusStatus, type AvSchedule } from "./ClamavCard";

// ── Shapes (06-clamav-contrats.md B-R, A-7) ──────────────────────────────────

export type AvScanStatus = "queued" | "running" | "completed" | "failed";

export interface AvScan {
  id: string;
  server_id: string;
  site_id: string;
  domain: string;
  trigger: "manual" | "scheduled";
  status: AvScanStatus;
  files_scanned: number;
  files_skipped: number;
  files_errors: number;
  infected_count: number;
  progress_done: number | null;
  progress_total: number | null;
  signatures_version: number | null;
  error: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export type AvDetectionStatus = "open" | "quarantined" | "deleted" | "ignored" | "restored";

export interface AvDetection {
  id: string;
  scan_id: string;
  site_id: string;
  domain: string;
  file_path: string;
  signature: string;
  size: number;
  sha256: string;
  status: AvDetectionStatus;
  quarantine_id: string | null;
  handled_by: string | null;
  handled_at: string | null;
  created_at: string;
  last_seen_at: string;
}

export interface AvQuarantineItem {
  quarantine_id: string;
  domain: string;
  original_path: string;
  signature: string | null;
  sha256: string;
  size: number;
  uid: number;
  gid: number;
  mode: number;
  quarantined_at: string;
}

export interface AvSiteStatus {
  installed: boolean;
  responding: boolean;
  last_scan: AvScan | null;
  open_detections: number;
}

const POLL_MS = 3000;

const isActive = (s: AvScan) => s.status === "queued" || s.status === "running";

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/** "42%" when the agent has counted the files, null before that. */
export function scanPercent(s: AvScan): number | null {
  if (s.progress_total == null || s.progress_total <= 0 || s.progress_done == null) return null;
  return Math.min(100, Math.floor((s.progress_done / s.progress_total) * 100));
}

const threats = (n: number) => `${n} ${n === 1 ? "threat" : "threats"}`;

function ScanStatusBadge({ scan }: { scan: AvScan }) {
  if (scan.status === "queued") {
    return <span className="px-2 py-0.5 bg-dark-700 text-dark-200 rounded text-xs font-medium">Queued</span>;
  }
  if (scan.status === "running") {
    const pct = scanPercent(scan);
    return (
      <span className="px-2 py-0.5 bg-accent-500/15 text-accent-400 rounded text-xs font-medium">
        {pct !== null ? `Scanning ${pct}%` : "Scanning"}
      </span>
    );
  }
  if (scan.status === "failed") {
    return <span className="px-2 py-0.5 bg-danger-500/15 text-danger-400 rounded text-xs font-medium">Failed</span>;
  }
  return scan.infected_count > 0 ? (
    <span className="px-2 py-0.5 bg-danger-500/15 text-danger-400 rounded text-xs font-medium">{threats(scan.infected_count)}</span>
  ) : (
    <span className="px-2 py-0.5 bg-rust-500/15 text-rust-400 rounded text-xs font-medium">Clean</span>
  );
}

const pad2 = (n: number) => String(n).padStart(2, "0");

// ── Security -> Antivirus ────────────────────────────────────────────────────

export type DetectionAction = "quarantine" | "delete" | "ignore" | "restore";

/** A detection action waiting for the operator's confirmation. */
export type DetectionPending =
  | { kind: "delete"; detection: AvDetection }
  | { kind: "ignore"; detection: AvDetection };

type PendingAction = DetectionPending | { kind: "purge"; item: AvQuarantineItem };

const DONE_LABEL: Record<DetectionAction, string> = {
  quarantine: "quarantined",
  delete: "deleted",
  ignore: "ignored",
  restore: "restored",
};

/** Owner route: `POST /antivirus/detections/{id}/{action}`. Resolves to the success text. */
export async function runDetectionAction(
  d: AvDetection,
  action: DetectionAction,
  body: Record<string, unknown> = {},
  path: string = d.file_path,
): Promise<string> {
  await api.post(`/antivirus/detections/${encodeURIComponent(d.id)}/${action}`, body);
  return `${path} ${DONE_LABEL[action]}`;
}

/** Path relative to the site directory (`/var/www/<domain>/`), or the full path. */
export function detectionRelPath(d: AvDetection): string {
  const root = `/var/www/${d.domain}/`;
  return d.file_path.startsWith(root) ? d.file_path.slice(root.length) : d.file_path;
}

/**
 * One detection with its actions: Quarantine / Delete / Ignore when open,
 * Restore when quarantined. Delete and Ignore only request a confirmation
 * (`onRequest`); the caller renders it with `DetectionDialogs`.
 */
export function DetectionRow({
  d,
  busy,
  showDomain,
  relativePath,
  onAction,
  onRequest,
}: {
  d: AvDetection;
  busy: string | null;
  showDomain: boolean;
  relativePath?: boolean;
  onAction: (d: AvDetection, action: DetectionAction) => void;
  onRequest: (p: DetectionPending) => void;
}) {
  const quarantined = d.status === "quarantined";
  return (
    <div className="px-5 py-3 flex flex-col md:flex-row md:items-center gap-2 md:gap-4">
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span
            className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase border ${
              quarantined
                ? "bg-warn-500/15 text-warn-400 border-warn-500/30"
                : "bg-danger-500/15 text-danger-400 border-danger-500/30"
            }`}
          >
            {d.signature}
          </span>
          {showDomain && <span className="text-xs text-dark-200">{d.domain}</span>}
          {quarantined && <span className="text-[10px] text-warn-400 uppercase font-mono">Quarantined</span>}
        </div>
        <p className="text-[11px] text-dark-300 font-mono break-all mt-1" title={relativePath ? d.file_path : undefined}>
          {relativePath ? detectionRelPath(d) : d.file_path}
        </p>
        <p className="text-[10px] text-dark-400 mt-0.5">
          {formatSize(d.size)} · first seen {formatDate(d.created_at)} · last seen {formatDate(d.last_seen_at)}
          {quarantined && d.handled_at && ` · quarantined ${formatDate(d.handled_at)}`}
        </p>
      </div>
      <div className="flex gap-1 shrink-0">
        {quarantined ? (
          <button
            onClick={() => onAction(d, "restore")}
            disabled={busy !== null}
            className="px-2 py-0.5 bg-rust-500/15 text-rust-400 rounded text-xs font-medium hover:bg-rust-500/25 disabled:opacity-50"
          >
            {busy === `restore:${d.id}` ? "Restoring..." : "Restore"}
          </button>
        ) : (
          <>
            <button
              onClick={() => onAction(d, "quarantine")}
              disabled={busy !== null}
              className="px-2 py-0.5 bg-warn-500/15 text-warn-400 rounded text-xs font-medium hover:bg-warn-500/25 disabled:opacity-50"
            >
              {busy === `quarantine:${d.id}` ? "Moving..." : "Quarantine"}
            </button>
            <button
              onClick={() => onRequest({ kind: "delete", detection: d })}
              disabled={busy !== null}
              className="px-2 py-0.5 bg-danger-500/15 text-danger-400 rounded text-xs font-medium hover:bg-danger-500/25 disabled:opacity-50"
            >
              {busy === `delete:${d.id}` ? "Deleting..." : "Delete"}
            </button>
            <button
              onClick={() => onRequest({ kind: "ignore", detection: d })}
              disabled={busy !== null}
              className="px-2 py-0.5 bg-dark-700 text-dark-200 rounded text-xs font-medium hover:bg-dark-600 disabled:opacity-50"
            >
              {busy === `ignore:${d.id}` ? "Ignoring..." : "Ignore"}
            </button>
          </>
        )}
      </div>
    </div>
  );
}

/**
 * Confirmations for Delete ("This cannot be undone") and Ignore (optional
 * note). `onCancel` must be stable: ConfirmDialog re-focuses Cancel whenever
 * it changes, which would steal focus from the note field.
 */
export function DetectionDialogs({
  pending,
  note,
  onNoteChange,
  onConfirm,
  onCancel,
}: {
  pending: DetectionPending | null;
  note: string;
  onNoteChange: (v: string) => void;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  if (pending?.kind === "delete") {
    return (
      <ConfirmDialog
        label={`Delete ${pending.detection.file_path}?\nThe file is removed from the site. This cannot be undone.`}
        confirmLabel="Delete"
        tone="danger"
        onConfirm={onConfirm}
        onCancel={onCancel}
      />
    );
  }
  if (pending?.kind === "ignore") {
    return (
      <ConfirmDialog
        label={`Ignore ${pending.detection.signature} in ${pending.detection.file_path}?\nThis exact file is no longer reported on this site. It is scanned again if it changes.`}
        confirmLabel="Ignore"
        tone="warn"
        onConfirm={onConfirm}
        onCancel={onCancel}
      >
        <label htmlFor="av-ignore-note" className="block text-xs text-dark-200 mb-1">Note (optional)</label>
        <input
          id="av-ignore-note"
          type="text"
          value={note}
          onChange={(e) => onNoteChange(e.target.value)}
          maxLength={500}
          placeholder="Why this is a false positive"
          className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 outline-none"
        />
      </ConfirmDialog>
    );
  }
  return null;
}

/**
 * Security -> Antivirus (admin): ClamAV state, schedule, "Scan all sites now",
 * scan history with live progress, open detections, and the quarantine.
 */
export default function AntivirusTab() {
  const { status, error: statusError, loading: statusLoading, refresh: refreshStatus, serverId } = useAntivirusStatus();
  const [sub, setSub] = useState<"scans" | "quarantine">("scans");
  const [scans, setScans] = useState<AvScan[]>([]);
  const [detections, setDetections] = useState<AvDetection[]>([]);
  const [quarantine, setQuarantine] = useState<AvQuarantineItem[]>([]);
  const [quarantinedDetections, setQuarantinedDetections] = useState<AvDetection[]>([]);
  const [listsError, setListsError] = useState("");
  const [quarantineError, setQuarantineError] = useState("");
  const [quarantineLoading, setQuarantineLoading] = useState(false);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [ignoreNote, setIgnoreNote] = useState("");
  // Stable on purpose: ConfirmDialog re-focuses Cancel whenever onCancel
  // changes, which would steal focus from the note field on every keystroke
  // and on every 3 s poll.
  const cancelPending = useCallback(() => setPending(null), []);

  // Schedule form
  const [schedEnabled, setSchedEnabled] = useState(true);
  const [schedHour, setSchedHour] = useState(3);
  const [schedDays, setSchedDays] = useState(1);
  const [savingSched, setSavingSched] = useState(false);
  const [schedule, setSchedule] = useState<AvSchedule | null>(null);

  useEffect(() => {
    const s = status?.schedule;
    if (!s) return;
    setSchedule(s);
    setSchedEnabled(s.enabled);
    setSchedHour(s.hour);
    setSchedDays(s.interval_days);
  }, [status?.schedule]);

  const sid = serverId ? encodeURIComponent(serverId) : "";

  const loadScans = useCallback(async () => {
    if (!sid) return [];
    const list = await api.get<AvScan[]>(`/antivirus/scans?server_id=${sid}&limit=50`);
    setScans(list);
    return list;
  }, [sid]);

  const loadDetections = useCallback(async () => {
    if (!sid) return;
    setDetections(await api.get<AvDetection[]>(`/antivirus/detections?server_id=${sid}&status=open`));
  }, [sid]);

  const loadLists = useCallback(async () => {
    try {
      await Promise.all([loadScans(), loadDetections()]);
      setListsError("");
    } catch (e) {
      setListsError(errText(e, "Could not load scans"));
    }
  }, [loadScans, loadDetections]);

  const loadQuarantine = useCallback(async () => {
    if (!sid) return;
    setQuarantineLoading(true);
    try {
      const [items, qd] = await Promise.all([
        api.get<AvQuarantineItem[]>(`/antivirus/quarantine?server_id=${sid}`),
        api.get<AvDetection[]>(`/antivirus/detections?server_id=${sid}&status=quarantined`),
      ]);
      setQuarantine(items);
      setQuarantinedDetections(qd);
      setQuarantineError("");
    } catch (e) {
      setQuarantineError(errText(e, "Could not load the quarantine"));
    } finally {
      setQuarantineLoading(false);
    }
  }, [sid]);

  useEffect(() => {
    setScans([]);
    setDetections([]);
    loadLists();
  }, [loadLists]);

  useEffect(() => {
    if (sub === "quarantine") loadQuarantine();
  }, [sub, loadQuarantine]);

  // Live progress: one 3 s poll while any scan is queued or running. Scans run
  // one site at a time, so detections are read on each tick too (a finished
  // site shows its threats without waiting for the whole batch), and once more
  // when the last scan ends.
  const anyActive = scans.some(isActive);
  const wasActive = useRef(false);
  useEffect(() => {
    if (!anyActive) {
      if (wasActive.current) {
        wasActive.current = false;
        loadDetections().catch(() => {});
      }
      return;
    }
    wasActive.current = true;
    const t = window.setInterval(() => {
      loadScans().catch(() => {});
      loadDetections().catch(() => {});
    }, POLL_MS);
    return () => window.clearInterval(t);
  }, [anyActive, loadScans, loadDetections]);

  const saveSchedule = async () => {
    if (!serverId) return;
    setSavingSched(true);
    setMessage(null);
    try {
      const s = await api.put<AvSchedule>("/antivirus/schedule", {
        server_id: serverId,
        enabled: schedEnabled,
        hour: schedHour,
        interval_days: schedDays,
      });
      setSchedule(s);
      setMessage({ text: "Schedule saved", type: "success" });
    } catch (e) {
      setMessage({ text: errText(e, "Could not save the schedule"), type: "error" });
    } finally {
      setSavingSched(false);
    }
  };

  const scanAll = async () => {
    if (!serverId) return;
    setBusy("scan-all");
    setMessage(null);
    try {
      const r = await api.post<{ scan_ids: string[] }>("/antivirus/scan", { server_id: serverId });
      const n = r.scan_ids?.length ?? 0;
      setMessage({ text: n > 0 ? `${n} ${n === 1 ? "site" : "sites"} queued for scanning` : "No sites to scan", type: "success" });
      await loadScans();
    } catch (e) {
      setMessage({ text: errText(e, "Could not start the scan"), type: "error" });
    } finally {
      setBusy(null);
    }
  };

  const detectionAction = async (d: AvDetection, action: DetectionAction, body: Record<string, unknown> = {}) => {
    setBusy(`${action}:${d.id}`);
    setMessage(null);
    try {
      setMessage({ text: await runDetectionAction(d, action, body), type: "success" });
      await loadDetections().catch(() => {});
      if (action === "restore" || action === "quarantine") loadQuarantine();
    } catch (e) {
      setMessage({ text: errText(e, "Action failed"), type: "error" });
    } finally {
      setBusy(null);
    }
  };

  const requestDetection = useCallback((p: DetectionPending) => {
    if (p.kind === "ignore") setIgnoreNote("");
    setPending(p);
  }, []);

  const purge = async (item: AvQuarantineItem) => {
    if (!serverId) return;
    setBusy(`purge:${item.quarantine_id}`);
    setMessage(null);
    try {
      await api.post(`/antivirus/quarantine/${encodeURIComponent(item.quarantine_id)}/delete?server_id=${sid}`, {});
      setMessage({ text: `${item.original_path} deleted permanently`, type: "success" });
      await loadQuarantine();
    } catch (e) {
      setMessage({ text: errText(e, "Could not delete the file"), type: "error" });
    } finally {
      setBusy(null);
    }
  };

  const confirmPending = () => {
    const p = pending;
    setPending(null);
    if (!p) return;
    if (p.kind === "delete") detectionAction(p.detection, "delete");
    else if (p.kind === "ignore") {
      const note = ignoreNote.trim();
      detectionAction(p.detection, "ignore", note ? { note } : {});
    } else purge(p.item);
  };

  const tz = status?.schedule?.timezone || schedule?.timezone || "UTC";
  const detectionByQuarantine = new Map(
    quarantinedDetections.filter((d) => d.quarantine_id).map((d) => [d.quarantine_id as string, d]),
  );

  if (statusLoading && !status) {
    return <div className="bg-dark-800 rounded-lg border border-dark-500 p-8 text-center text-sm text-dark-300">Loading antivirus status...</div>;
  }

  if (!status) {
    return (
      <div className="bg-dark-800 rounded-lg border border-dark-500 p-8 text-center text-sm text-danger-400">
        {statusError || "Could not read the antivirus status"}
      </div>
    );
  }

  const canScan = status.installed && status.responding;

  return (
    <div className="space-y-4">
      <DetectionDialogs
        pending={pending && pending.kind !== "purge" ? pending : null}
        note={ignoreNote}
        onNoteChange={setIgnoreNote}
        onConfirm={confirmPending}
        onCancel={cancelPending}
      />
      {pending?.kind === "purge" && (
        <ConfirmDialog
          label={`Delete ${pending.item.original_path} permanently?\nThe quarantined copy is erased and can no longer be restored. This cannot be undone.`}
          confirmLabel="Delete permanently"
          tone="danger"
          onConfirm={confirmPending}
          onCancel={cancelPending}
        />
      )}

      {message && (
        <div className={`px-4 py-2 rounded-lg text-sm border ${message.type === "success" ? "bg-rust-500/10 text-rust-400 border-rust-500/20" : "bg-danger-500/10 text-danger-400 border-danger-500/20"}`}>
          {message.text}
        </div>
      )}

      {/* Status */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 p-5">
        <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">ClamAV</h3>
              {status.installed && (
                <span className={`w-2.5 h-2.5 rounded-full ${status.responding ? "bg-rust-500" : "bg-warn-500"}`} />
              )}
            </div>
            <p className="text-sm text-dark-100 mt-1">
              {!status.supported
                ? "Not supported on this server"
                : !status.installed
                  ? "Not installed"
                  : status.responding
                    ? `Responding${status.version ? ` (${status.version})` : ""}`
                    : status.running
                      ? "Running but not responding"
                      : "Stopped"}
            </p>
            {status.installed && (
              <p className="text-xs text-dark-300 mt-1">
                Signatures {status.signatures ? status.signatures.version : "-"}
                {status.signatures?.updated_at && `, updated ${formatDate(status.signatures.updated_at)}`}
                {status.memory_bytes != null && ` · Memory ${formatSize(status.memory_bytes)}`}
                {` · Mail antivirus ${status.mail?.enabled ? "on" : "off"}`}
              </p>
            )}
            {!status.installed && status.supported && (
              <p className="text-xs text-dark-300 mt-1">
                Install ClamAV in{" "}
                <Link to="/settings?tab=services" className="text-accent-400 hover:text-accent-300">Settings &gt; Services</Link>{" "}
                to scan site files.
              </p>
            )}
          </div>
          {status.installed && (
            <button
              onClick={scanAll}
              disabled={!canScan || busy === "scan-all"}
              title={!status.responding ? "ClamAV is not responding" : undefined}
              className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 shrink-0"
            >
              {busy === "scan-all" ? "Queuing..." : "Scan all sites now"}
            </button>
          )}
        </div>
        {statusError && <p className="text-xs text-danger-400 mt-2">{statusError}</p>}
      </div>

      {/* Schedule */}
      {status.installed && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 p-5">
          <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-3">Scheduled scan</h3>
          <div className="flex flex-wrap items-end gap-4">
            <label className="flex items-center gap-2 text-sm text-dark-100">
              <input type="checkbox" checked={schedEnabled} onChange={(e) => setSchedEnabled(e.target.checked)} />
              Scan all sites automatically
            </label>
            <div>
              <label htmlFor="av-hour" className="block text-xs text-dark-200 mb-1">Hour ({tz})</label>
              <select
                id="av-hour"
                value={schedHour}
                onChange={(e) => setSchedHour(Number(e.target.value))}
                className="px-3 py-2 border border-dark-500 rounded-lg text-sm bg-dark-900 outline-none focus:ring-2 focus:ring-accent-500"
              >
                {Array.from({ length: 24 }, (_, h) => (
                  <option key={h} value={h}>{`${pad2(h)}:00`}</option>
                ))}
              </select>
            </div>
            <div>
              <label htmlFor="av-days" className="block text-xs text-dark-200 mb-1">Every (days)</label>
              <input
                id="av-days"
                type="number"
                min={1}
                max={30}
                value={schedDays}
                onChange={(e) => {
                  const v = Math.round(Number(e.target.value));
                  setSchedDays(Number.isFinite(v) ? Math.min(30, Math.max(1, v)) : 1);
                }}
                className="w-24 px-3 py-2 border border-dark-500 rounded-lg text-sm outline-none focus:ring-2 focus:ring-accent-500"
              />
            </div>
            <button
              onClick={saveSchedule}
              disabled={savingSched}
              className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50"
            >
              {savingSched ? "Saving..." : "Save"}
            </button>
          </div>
          {schedule && (
            <p className="text-xs text-dark-300 mt-3">
              Last run: {schedule.last_run_at ? formatDate(schedule.last_run_at) : "never"}
              {schedule.enabled && schedule.next_run_at && ` · Next run: ${formatDate(schedule.next_run_at)}`}
            </p>
          )}
        </div>
      )}

      {/* Sub-tabs */}
      <div className="flex gap-1 bg-dark-700 rounded-lg p-1 w-fit">
        {(["scans", "quarantine"] as const).map((k) => (
          <button
            key={k}
            onClick={() => setSub(k)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              sub === k ? "bg-dark-800 text-dark-50 shadow-sm" : "text-dark-200 hover:text-dark-100"
            }`}
          >
            {k === "scans" ? `Detections and scans${detections.length > 0 ? ` (${detections.length})` : ""}` : "Quarantine"}
          </button>
        ))}
      </div>

      {sub === "scans" && (
        <>
          {listsError && (
            <div className="px-4 py-2 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20">{listsError}</div>
          )}

          {/* Open detections */}
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
            <div className="px-5 py-3 border-b border-dark-600">
              <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Open detections</h3>
            </div>
            {detections.length === 0 ? (
              <div className="p-6 text-center text-sm text-dark-300">No open detections</div>
            ) : (
              <div className="divide-y divide-dark-600">
                {detections.map((d) => (
                  <DetectionRow
                    key={d.id}
                    d={d}
                    busy={busy}
                    showDomain
                    onAction={detectionAction}
                    onRequest={requestDetection}
                  />
                ))}
              </div>
            )}
          </div>

          {/* Scans */}
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
            <div className="px-5 py-3 border-b border-dark-600 flex items-center justify-between">
              <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Scans</h3>
              {anyActive && <span className="text-[10px] text-dark-400">Refreshing every 3 s</span>}
            </div>
            {scans.length === 0 ? (
              <div className="p-6 text-center text-sm text-dark-300">No antivirus scans yet</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-left text-[10px] text-dark-400 uppercase tracking-wider border-b border-dark-600">
                      <th className="px-5 py-2 font-medium">Site</th>
                      <th className="px-3 py-2 font-medium">Trigger</th>
                      <th className="px-3 py-2 font-medium">Result</th>
                      <th className="px-3 py-2 font-medium">Files</th>
                      <th className="px-3 py-2 font-medium">Started</th>
                      <th className="px-3 py-2 font-medium">Finished</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-600">
                    {scans.map((s) => (
                      <tr key={s.id}>
                        <td className="px-5 py-2 text-dark-100">{s.domain}</td>
                        <td className="px-3 py-2 text-dark-300 text-xs capitalize">{s.trigger}</td>
                        <td className="px-3 py-2">
                          <ScanStatusBadge scan={s} />
                          {s.error && <p className="text-[11px] text-danger-400 mt-1 max-w-xs break-words">{s.error}</p>}
                        </td>
                        <td className="px-3 py-2 text-xs text-dark-200 font-mono whitespace-nowrap">
                          {s.status === "running" && s.progress_total
                            ? `${s.progress_done ?? 0} / ${s.progress_total}`
                            : s.files_scanned}
                          {(s.files_skipped > 0 || s.files_errors > 0) && (
                            <span
                              className="text-dark-400"
                              title="Skipped: larger than 25 MB. Errors: clamd could not read the file."
                            >
                              {s.files_skipped > 0 && ` · ${s.files_skipped} skipped`}
                              {s.files_errors > 0 && ` · ${s.files_errors} errors`}
                            </span>
                          )}
                        </td>
                        <td className="px-3 py-2 text-xs text-dark-300 whitespace-nowrap">
                          {s.started_at ? formatDate(s.started_at) : formatDate(s.created_at)}
                        </td>
                        <td className="px-3 py-2 text-xs text-dark-300 whitespace-nowrap">
                          {s.completed_at ? formatDate(s.completed_at) : "-"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {sub === "quarantine" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
          <div className="px-5 py-3 border-b border-dark-600">
            <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Quarantine</h3>
            <p className="text-xs text-dark-300 mt-0.5">Files moved out of the sites. They are kept when ClamAV is uninstalled.</p>
          </div>
          {quarantineError && <p className="px-5 py-3 text-sm text-danger-400">{quarantineError}</p>}
          {quarantineLoading && quarantine.length === 0 ? (
            <div className="p-6 text-center text-sm text-dark-300">Loading...</div>
          ) : quarantine.length === 0 ? (
            <div className="p-6 text-center text-sm text-dark-300">The quarantine is empty</div>
          ) : (
            <div className="divide-y divide-dark-600">
              {quarantine.map((q) => {
                const det = detectionByQuarantine.get(q.quarantine_id);
                const legacy = q.quarantine_id.startsWith("legacy:");
                return (
                  <div key={q.quarantine_id} className="px-5 py-3 flex flex-col md:flex-row md:items-center gap-2 md:gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        {q.signature && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-semibold uppercase border bg-warn-500/15 text-warn-400 border-warn-500/30">
                            {q.signature}
                          </span>
                        )}
                        <span className="text-xs text-dark-200">{q.domain}</span>
                      </div>
                      <p className="text-[11px] text-dark-300 font-mono break-all mt-1">{q.original_path}</p>
                      <p className="text-[10px] text-dark-400 mt-0.5">
                        {formatSize(q.size)} · quarantined {formatDate(q.quarantined_at)}
                      </p>
                    </div>
                    <div className="flex gap-1 shrink-0">
                      {det ? (
                        <button
                          onClick={() => detectionAction(det, "restore")}
                          disabled={busy !== null}
                          className="px-2 py-0.5 bg-rust-500/15 text-rust-400 rounded text-xs font-medium hover:bg-rust-500/25 disabled:opacity-50"
                        >
                          {busy === `restore:${det.id}` ? "Restoring..." : "Restore"}
                        </button>
                      ) : (
                        <span
                          className="px-2 py-0.5 text-[10px] text-dark-400"
                          title={
                            legacy
                              ? "Quarantined before restore was supported: no metadata for this file"
                              : "Not quarantined from an antivirus detection: restore it from the server"
                          }
                        >
                          No restore
                        </span>
                      )}
                      <button
                        onClick={() => setPending({ kind: "purge", item: q })}
                        disabled={busy !== null}
                        className="px-2 py-0.5 bg-danger-500/15 text-danger-400 rounded text-xs font-medium hover:bg-danger-500/25 disabled:opacity-50"
                      >
                        {busy === `purge:${q.quarantine_id}` ? "Deleting..." : "Delete permanently"}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── SiteDetail: "Scan now" + badge ───────────────────────────────────────────

/**
 * Last scan badge and "Scan now" for one site. Uses only the owner routes
 * (`/antivirus/site-status`, `/antivirus/scan`), so it works for a site owner.
 * Renders nothing when ClamAV is not installed or the status cannot be read.
 */
export function SiteAntivirusStatus({
  siteId,
  serverId,
  showSecurityLink,
  refreshKey = 0,
  onStatus,
}: {
  siteId: string;
  serverId: string | null | undefined;
  showSecurityLink: boolean;
  /** Bump to re-read the status (e.g. after a detection action). */
  refreshKey?: number;
  /** Receives every status read (null while loading another site). */
  onStatus?: (st: AvSiteStatus | null) => void;
}) {
  const [st, setSt] = useState<AvSiteStatus | null>(null);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setSt(await api.get<AvSiteStatus>(`/antivirus/site-status?site_id=${encodeURIComponent(siteId)}`));
    } catch {
      // Hidden only when the first read fails; a failed poll keeps the last state.
    }
  }, [siteId]);

  useEffect(() => {
    setSt(null);
    load();
  }, [load]);

  const firstRefresh = useRef(true);
  useEffect(() => {
    if (firstRefresh.current) {
      firstRefresh.current = false;
      return;
    }
    load();
  }, [refreshKey, load]);

  useEffect(() => {
    onStatus?.(st);
  }, [st, onStatus]);

  const active = st?.last_scan ? isActive(st.last_scan) : false;
  useEffect(() => {
    if (!active) return;
    const t = window.setInterval(load, POLL_MS);
    return () => window.clearInterval(t);
  }, [active, load]);

  if (!st || !st.installed) return null;

  const scanNow = async () => {
    setStarting(true);
    setError("");
    try {
      const sv = serverId ?? st.last_scan?.server_id;
      await api.post("/antivirus/scan", sv ? { server_id: sv, site_id: siteId } : { site_id: siteId });
      await load();
    } catch (e) {
      setError(errText(e, "Could not start the scan"));
    } finally {
      setStarting(false);
    }
  };

  const s = st.last_scan;
  let badge: { text: string; cls: string };
  if (!s) badge = { text: "Never scanned", cls: "bg-dark-700 text-dark-200" };
  else if (s.status === "queued") badge = { text: "Scan queued", cls: "bg-dark-700 text-dark-200" };
  else if (s.status === "running") {
    const pct = scanPercent(s);
    badge = { text: pct !== null ? `Scanning ${pct}%` : "Scanning", cls: "bg-accent-500/10 text-accent-400" };
  } else if (st.open_detections > 0) badge = { text: threats(st.open_detections), cls: "bg-danger-500/10 text-danger-400" };
  else if (s.status === "failed") badge = { text: "Scan failed", cls: "bg-warn-500/10 text-warn-400" };
  else badge = { text: "Clean", cls: "bg-rust-500/10 text-rust-400" };

  const title = [
    s?.completed_at ? `Last scan: ${formatDate(s.completed_at)}` : null,
    s?.status === "failed" && s.error ? s.error : null,
  ].filter(Boolean).join(" · ");

  return (
    <>
      <span title={title || undefined} className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono ${badge.cls}`}>
        Antivirus: {badge.text}
      </span>
      <button
        onClick={scanNow}
        disabled={starting || active || !st.responding}
        title={!st.responding ? "ClamAV is not responding" : undefined}
        className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded text-xs font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
      >
        {starting ? "Starting..." : "Scan now"}
      </button>
      {showSecurityLink && (
        <Link to="/security?tab=antivirus" className="text-xs text-accent-400 hover:text-accent-300">
          View detections
        </Link>
      )}
      {error && <span className="text-xs text-danger-400">{error}</span>}
    </>
  );
}

// ── SiteDetail: this site's detections ───────────────────────────────────────

/**
 * Open and quarantined detections of one site, with their actions. Uses only
 * owner routes (`/antivirus/detections?site_id=`, `/antivirus/detections/{id}/...`),
 * so a site owner can act without the admin Security page. Re-reads whenever
 * the site status changes (scan finished, threat count changed). Renders
 * nothing when ClamAV is not installed or there is nothing to show.
 */
export function SiteAntivirusDetections({
  siteId,
  status,
  onChanged,
}: {
  siteId: string;
  status: AvSiteStatus | null;
  /** Called after a successful action so the badge can re-read its count. */
  onChanged?: () => void;
}) {
  const [items, setItems] = useState<AvDetection[]>([]);
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [pending, setPending] = useState<DetectionPending | null>(null);
  const [note, setNote] = useState("");
  const cancelPending = useCallback(() => setPending(null), []);

  const installed = status?.installed ?? false;
  const scan = status?.last_scan;
  // Changes when a scan starts, progresses to an end, or the open count moves.
  const statusKey = `${scan?.id ?? ""}:${scan?.status ?? ""}:${status?.open_detections ?? 0}`;

  const load = useCallback(async () => {
    const q = `site_id=${encodeURIComponent(siteId)}`;
    const [open, quarantined] = await Promise.all([
      api.get<AvDetection[]>(`/antivirus/detections?${q}&status=open`),
      api.get<AvDetection[]>(`/antivirus/detections?${q}&status=quarantined`),
    ]);
    setItems([...open, ...quarantined]);
  }, [siteId]);

  useEffect(() => {
    setItems([]);
    setMessage(null);
  }, [siteId]);

  useEffect(() => {
    if (!installed) return;
    load().catch(() => {});
  }, [installed, statusKey, load]);

  const act = async (d: AvDetection, action: DetectionAction, body: Record<string, unknown> = {}) => {
    setBusy(`${action}:${d.id}`);
    setMessage(null);
    try {
      setMessage({ text: await runDetectionAction(d, action, body, detectionRelPath(d)), type: "success" });
      onChanged?.();
    } catch (e) {
      // 409 "The file changed since it was scanned" is shown as is.
      setMessage({ text: errText(e, "Action failed"), type: "error" });
    } finally {
      setBusy(null);
      await load().catch(() => {});
    }
  };

  const request = useCallback((p: DetectionPending) => {
    if (p.kind === "ignore") setNote("");
    setPending(p);
  }, []);

  const confirm = () => {
    const p = pending;
    setPending(null);
    if (!p) return;
    if (p.kind === "delete") act(p.detection, "delete");
    else {
      const n = note.trim();
      act(p.detection, "ignore", n ? { note: n } : {});
    }
  };

  if (!installed || (items.length === 0 && !message)) return null;

  const openCount = items.filter((d) => d.status === "open").length;
  const quarantinedCount = items.length - openCount;

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
      <DetectionDialogs
        pending={pending}
        note={note}
        onNoteChange={setNote}
        onConfirm={confirm}
        onCancel={cancelPending}
      />
      <div className="px-5 py-3 border-b border-dark-600">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Antivirus</h3>
        <p className="text-xs text-dark-300 mt-0.5">
          {items.length === 0
            ? "No open or quarantined detections"
            : [
                openCount > 0 ? `${threats(openCount)} found` : null,
                quarantinedCount > 0 ? `${quarantinedCount} in quarantine` : null,
              ].filter(Boolean).join(", ")}
        </p>
      </div>
      {message && (
        <div
          className={`mx-5 my-3 px-4 py-2 rounded-lg text-sm border ${
            message.type === "success"
              ? "bg-rust-500/10 text-rust-400 border-rust-500/20"
              : "bg-danger-500/10 text-danger-400 border-danger-500/20"
          }`}
        >
          {message.text}
        </div>
      )}
      {items.length > 0 && (
        <div className="divide-y divide-dark-600">
          {items.map((d) => (
            <DetectionRow
              key={d.id}
              d={d}
              busy={busy}
              showDomain={false}
              relativePath
              onAction={act}
              onRequest={request}
            />
          ))}
        </div>
      )}
    </div>
  );
}
