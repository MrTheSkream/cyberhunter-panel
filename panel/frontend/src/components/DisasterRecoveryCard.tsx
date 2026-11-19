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

type DrRestorePhase = "downloading" | "verifying" | "decrypting" | "starting" | "handed_off" | "failed";

interface DrRestoreProgress {
  archive: string;
  snapshot_id: string;
  phase: DrRestorePhase;
  started_at: string;
  updated_at: string;
  error: string | null;
}

interface DrLastRestore {
  snapshot_id: string;
  ok: boolean;
  stage: string;
  detail: string;
  finished_at: string;
  mode?: string;
}

interface DrVhostSite {
  domain: string;
  status: "rebuilt" | "failed" | "skipped";
  remapped_from: string | null;
  detail: string | null;
}

interface DrVhostRebuild {
  started_at: string;
  finished_at: string;
  ok: boolean;
  sites: DrVhostSite[];
  remapped: number;
  rebuilt: number;
  failed: number;
  nginx_test: { ok: boolean; output: string } | null;
  reload: { ok: boolean; detail: string } | null;
  key_paths: { destination: string; from: string; to: string }[];
  errors: string[];
}

interface DrRehydrateItem {
  kind: "site" | "database";
  name: string;
  filename: string | null;
  destination: string | null;
  status: "restored" | "failed" | "skipped";
  detail: string;
}

interface DrRehydrate {
  started_at: string;
  finished_at: string | null;
  items: DrRehydrateItem[];
  restored: number;
  failed: number;
  skipped: number;
}

interface DrRestoreStatus {
  progress: DrRestoreProgress | null;
  last_restore: DrLastRestore | null;
  vhost_rebuild_pending: boolean;
  vhost_rebuild: DrVhostRebuild | null;
  rehydrate_running: boolean;
  rehydrate: DrRehydrate | null;
}

interface DrRestoreStarted {
  started: boolean;
  snapshot_id: string;
  archive: string;
}

/** A remote restore being followed. `baseline` is the last_restore.finished_at
 *  seen when following started: a different value means a newer verdict. */
interface RestoreTrack {
  startedAt: number;
  baseline: string | null;
  archive: string | null;
}

type RestoreFetch = { kind: "ok"; data: DrRestoreStatus } | { kind: "auth" } | { kind: "down" };

const PHASE_LABELS: Record<DrRestorePhase, string> = {
  downloading: "Downloading",
  verifying: "Verifying checksum",
  decrypting: "Decrypting",
  starting: "Starting the restore",
  handed_off: "Handed off: the panel is restarting",
  failed: "Failed",
};

const DEFAULT_SCHEDULE = "30 3 * * *";
const POLL_MS = 5000;
const RESTORE_POLL_MS = 3000;
const RESTORE_TRACK_MAX_MS = 20 * 60 * 1000;

const BADGE = "px-1.5 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap";
const BADGE_OK = "bg-rust-500/10 text-rust-400 border-rust-500/20";
const BADGE_BAD = "bg-danger-500/10 text-danger-400 border-danger-500/20";
const BADGE_MUTED = "bg-dark-700 text-dark-400 border-dark-600";
const SMALL_BTN =
  "px-2 py-1 bg-dark-700 hover:bg-dark-600 text-dark-300 border border-dark-600 rounded text-xs whitespace-nowrap disabled:opacity-50";

function itemBadge(status: string): string {
  if (status === "rebuilt" || status === "restored") return BADGE_OK;
  if (status === "failed") return BADGE_BAD;
  return BADGE_MUTED;
}

/** The remote restore report: progress, last verdict, vhost rebuild, rehydrate. */
function RemoteRestoreReport({
  data,
  following,
  unreachable,
  timedOut,
}: {
  data: DrRestoreStatus | null;
  following: boolean;
  unreachable: boolean;
  timedOut: boolean;
}) {
  if (!data) return null;
  const { progress, last_restore: last, vhost_rebuild: vr, rehydrate: rh } = data;
  return (
    <div className="space-y-3">
      {following && unreachable && (
        <div className="px-3 py-2 rounded-lg text-xs border bg-warn-500/10 text-warn-400 border-warn-500/20">
          The panel is restarting. This page keeps checking.
        </div>
      )}
      {timedOut && (
        <div className="px-3 py-2 rounded-lg text-xs border bg-warn-500/10 text-warn-400 border-warn-500/20">
          Stopped checking after 20 minutes. Reload the page to check again.
        </div>
      )}

      {progress && (
        <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="text-dark-400">
              Restore progress:{" "}
              <span className={`font-medium ${progress.phase === "failed" ? "text-danger-400" : "text-dark-100"}`}>
                {PHASE_LABELS[progress.phase] ?? progress.phase}
              </span>
            </span>
            <span className="text-dark-400">
              Archive: <span className="font-mono text-dark-200 break-all">{progress.archive}</span>
            </span>
            <span className="text-dark-400">
              Started: <span className="text-dark-200">{formatDate(progress.started_at)}</span>
            </span>
            <span className="text-dark-400">
              Updated: <span className="text-dark-200">{formatDate(progress.updated_at)}</span>
            </span>
          </div>
          {progress.error && <div className="mt-1 text-danger-400 break-words">{progress.error}</div>}
        </div>
      )}

      {last && (
        <div
          className={`px-3 py-2 rounded-lg text-xs border ${
            last.ok ? "bg-rust-500/10 text-rust-400 border-rust-500/20" : BADGE_BAD
          }`}
        >
          <div className="font-medium">
            {last.ok ? "Last restore succeeded" : "Last restore needs attention"}
            <span className="font-normal text-dark-400"> ({formatDate(last.finished_at)})</span>
          </div>
          {!last.ok && (
            <div className="mt-1 break-words">
              <span className="font-mono">{last.stage}</span>
              {last.detail ? `: ${last.detail}` : ""}
            </div>
          )}
          {last.ok && last.detail && <div className="mt-1 text-dark-300 break-words">{last.detail}</div>}
        </div>
      )}

      {data.vhost_rebuild_pending ? (
        <div className="text-xs text-dark-300">Rebuilding site configurations...</div>
      ) : (
        vr && (
          <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 text-xs">
            <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mb-2">
              <span className="text-dark-200 font-medium">Site configurations</span>
              <span className={`${BADGE} ${vr.ok ? BADGE_OK : BADGE_BAD}`}>{vr.ok ? "OK" : "Needs attention"}</span>
              <span className="text-dark-400">
                Rebuilt <span className="text-dark-200">{vr.rebuilt}</span>
              </span>
              <span className="text-dark-400">
                Failed <span className="text-dark-200">{vr.failed}</span>
              </span>
              <span className="text-dark-400">
                Moved to the primary IP <span className="text-dark-200">{vr.remapped}</span>
              </span>
              <span className="text-dark-400">Finished {formatDate(vr.finished_at)}</span>
            </div>
            {vr.sites.length > 0 && (
              <div className="overflow-x-auto mb-2">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-dark-400 border-b border-dark-700">
                      <th className="px-2 py-1.5 font-normal">Domain</th>
                      <th className="px-2 py-1.5 font-normal">Status</th>
                      <th className="px-2 py-1.5 font-normal">Detail</th>
                    </tr>
                  </thead>
                  <tbody>
                    {vr.sites.map(site => (
                      <tr key={site.domain} className="border-b border-dark-700/50">
                        <td className="px-2 py-1.5 font-mono text-dark-200 break-all">{site.domain}</td>
                        <td className="px-2 py-1.5">
                          <span className={`${BADGE} ${itemBadge(site.status)}`}>{site.status}</span>
                        </td>
                        <td className="px-2 py-1.5 text-dark-300 break-words">
                          {site.remapped_from && <div>Moved to the primary IP (was {site.remapped_from})</div>}
                          {site.detail && <div>{site.detail}</div>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            {vr.nginx_test && (
              <div className={vr.nginx_test.ok ? "text-dark-300" : "text-danger-400"}>
                nginx test: {vr.nginx_test.ok ? "passed" : "failed"}
                {!vr.nginx_test.ok && vr.nginx_test.output && (
                  <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px]">{vr.nginx_test.output}</pre>
                )}
              </div>
            )}
            {vr.reload && (
              <div className={vr.reload.ok ? "text-dark-300" : "text-danger-400"}>
                nginx reload: {vr.reload.ok ? "done" : "failed"}
                {vr.reload.detail ? ` (${vr.reload.detail})` : ""}
              </div>
            )}
            {vr.key_paths.length > 0 && (
              <div className="mt-2 text-dark-400">
                Backup destination key paths rewritten:
                <ul className="mt-1 space-y-0.5">
                  {vr.key_paths.map((k, i) => (
                    <li key={`${k.destination}-${i}`} className="break-all">
                      {k.destination}: <span className="font-mono text-dark-300">{k.from}</span> to{" "}
                      <span className="font-mono text-dark-200">{k.to}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {vr.errors.length > 0 && (
              <ul className="mt-2 space-y-0.5 text-danger-400">
                {vr.errors.map((err, i) => (
                  <li key={i} className="break-words">{err}</li>
                ))}
              </ul>
            )}
          </div>
        )
      )}

      {data.rehydrate_running && (
        <div className="text-xs text-dark-300">Restoring sites and databases from remote backups...</div>
      )}
      {rh && (
        <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mb-2">
            <span className="text-dark-200 font-medium">Sites and databases</span>
            <span className="text-dark-400">
              Restored <span className="text-dark-200">{rh.restored}</span>
            </span>
            <span className="text-dark-400">
              Failed <span className="text-dark-200">{rh.failed}</span>
            </span>
            <span className="text-dark-400">
              Skipped <span className="text-dark-200">{rh.skipped}</span>
            </span>
            <span className="text-dark-400">
              {rh.finished_at ? `Finished ${formatDate(rh.finished_at)}` : `Started ${formatDate(rh.started_at)}`}
            </span>
          </div>
          {rh.items.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-dark-400 border-b border-dark-700">
                    <th className="px-2 py-1.5 font-normal">Kind</th>
                    <th className="px-2 py-1.5 font-normal">Name</th>
                    <th className="px-2 py-1.5 font-normal">File</th>
                    <th className="px-2 py-1.5 font-normal">Destination</th>
                    <th className="px-2 py-1.5 font-normal">Status</th>
                    <th className="px-2 py-1.5 font-normal">Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {rh.items.map((it, i) => (
                    <tr key={`${it.kind}-${it.name}-${i}`} className="border-b border-dark-700/50">
                      <td className="px-2 py-1.5 text-dark-300">{it.kind}</td>
                      <td className="px-2 py-1.5 font-mono text-dark-200 break-all">{it.name}</td>
                      <td className="px-2 py-1.5 font-mono text-dark-400 break-all">{it.filename || "-"}</td>
                      <td className="px-2 py-1.5 text-dark-300">{it.destination || "-"}</td>
                      <td className="px-2 py-1.5">
                        <span className={`${BADGE} ${itemBadge(it.status)}`}>{it.status}</span>
                      </td>
                      <td className="px-2 py-1.5 text-dark-300 break-words">{it.detail}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
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

  const [idCopied, setIdCopied] = useState(false);

  // Remote restore (steps 2.5 and 2.6).
  const [restore, setRestore] = useState<DrRestoreStatus | null>(null);
  const [restoreUnreachable, setRestoreUnreachable] = useState(false);
  const [restoreTrack, setRestoreTrack] = useState<RestoreTrack | null>(null);
  const [restoreTimedOut, setRestoreTimedOut] = useState(false);
  const [rehydrateTrack, setRehydrateTrack] = useState(false);
  const [rehydrateConfirm, setRehydrateConfirm] = useState(false);
  const [rehydrateStarting, setRehydrateStarting] = useState(false);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // Restore dialog. The pasted recovery identity lives only here, and is
  // cleared on close and right after it is sent.
  const [restoreTarget, setRestoreTarget] = useState<DrRemoteSnapshot | null>(null);
  const [recoveryIdentity, setRecoveryIdentity] = useState("");
  const [restoreAck, setRestoreAck] = useState(false);
  const [restoreSubmitting, setRestoreSubmitting] = useState(false);
  const [restoreError, setRestoreError] = useState("");

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

  // GET /api/dr/restore. Only a 401 ends a follow: the panel stops while a
  // restore runs, so network errors, 502/503 and other API errors mean "the
  // panel is restarting", not "give up".
  const fetchRestore = useCallback(async (): Promise<RestoreFetch> => {
    try {
      const data = await api.get<DrRestoreStatus>("/dr/restore");
      setRestore(data);
      setRestoreUnreachable(false);
      return { kind: "ok", data };
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 401) return { kind: "auth" };
      setRestoreUnreachable(true);
      return { kind: "down" };
    }
  }, []);

  // On mount: pick up a restore or rehydrate already in flight.
  useEffect(() => {
    void (async () => {
      const res = await fetchRestore();
      if (res.kind !== "ok") return;
      const d = res.data;
      const p = d.progress;
      const last = d.last_restore;
      const verdictIsNewer =
        !!p && !!last && new Date(last.finished_at).getTime() >= new Date(p.started_at).getTime();
      if ((p && p.phase !== "failed" && !verdictIsNewer) || d.vhost_rebuild_pending) {
        setRestoreTrack({
          startedAt: Date.now(),
          // A verdict newer than the progress is already this restore's: only
          // the vhost rebuild remains to wait for.
          baseline: verdictIsNewer ? null : last?.finished_at ?? null,
          archive: null,
        });
      }
      if (d.rehydrate_running) setRehydrateTrack(true);
    })();
  }, [fetchRestore]);

  // Follow a remote restore every 3 s, for at most 20 minutes.
  useEffect(() => {
    if (!restoreTrack) return;
    let cancelled = false;
    const tick = async () => {
      if (Date.now() - restoreTrack.startedAt > RESTORE_TRACK_MAX_MS) {
        setRestoreTrack(null);
        setRestoreTimedOut(true);
        return;
      }
      const res = await fetchRestore();
      if (cancelled) return;
      if (res.kind === "auth") {
        setRestoreTrack(null);
        return;
      }
      if (res.kind !== "ok") return;
      const d = res.data;
      const done =
        !!d.last_restore && d.last_restore.finished_at !== restoreTrack.baseline && !d.vhost_rebuild_pending;
      const failed =
        d.progress?.phase === "failed" &&
        (restoreTrack.archive === null || d.progress.archive === restoreTrack.archive);
      if (done || failed) {
        setRestoreTrack(null);
        void load();
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), RESTORE_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [restoreTrack, fetchRestore, load]);

  // Follow a rehydrate every 3 s while it runs.
  useEffect(() => {
    if (!rehydrateTrack) return;
    let cancelled = false;
    const tick = async () => {
      const res = await fetchRestore();
      if (cancelled) return;
      if (res.kind === "auth" || (res.kind === "ok" && !res.data.rehydrate_running)) {
        setRehydrateTrack(false);
      }
    };
    const id = window.setInterval(() => void tick(), RESTORE_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [rehydrateTrack, fetchRestore]);

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

  const copyInstallId = async () => {
    if (!status?.install_id) return;
    try {
      await navigator.clipboard.writeText(status.install_id);
      setIdCopied(true);
      setTimeout(() => setIdCopied(false), 2000);
    } catch {
      flash("Could not copy to the clipboard. Select the Install ID instead.", "error");
    }
  };

  const downloadRemote = async (r: DrRemoteSnapshot) => {
    setDownloadingId(r.id);
    try {
      const res = await fetch(`/api/dr/remote-snapshots/${encodeURIComponent(r.id)}/download`, {
        credentials: "same-origin",
        headers: { "X-Requested-With": "DockPanel" },
      });
      if (!res.ok) {
        const data = (await res.json().catch(() => ({}))) as { error?: string };
        throw new Error(data.error || `Download failed (${res.status})`);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = r.filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 0);
    } catch (e: unknown) {
      flash(e instanceof Error ? e.message : "Could not download the archive", "error");
    } finally {
      setDownloadingId(null);
    }
  };

  const openRestore = (r: DrRemoteSnapshot) => {
    setRecoveryIdentity("");
    setRestoreAck(false);
    setRestoreError("");
    setRestoreTarget(r);
  };

  const closeRestore = () => {
    if (restoreSubmitting) return;
    setRecoveryIdentity("");
    setRestoreAck(false);
    setRestoreError("");
    setRestoreTarget(null);
  };

  const submitRestore = async () => {
    if (!restoreTarget || !restoreAck || !recoveryIdentity.trim()) return;
    const identity = recoveryIdentity;
    // Cleared as soon as it is sent, whatever the outcome.
    setRecoveryIdentity("");
    setRestoreSubmitting(true);
    setRestoreError("");
    const baseline = restore?.last_restore?.finished_at ?? null;
    try {
      const data = await api.post<DrRestoreStarted>(
        `/dr/remote-snapshots/${encodeURIComponent(restoreTarget.id)}/restore`,
        { identity },
      );
      setRestoreAck(false);
      setRestoreTarget(null);
      setRestoreTimedOut(false);
      setRestoreTrack({ startedAt: Date.now(), baseline, archive: data.archive || null });
      flash("Restore started. The panel stops and restarts during the restore.", "success");
    } catch (e: unknown) {
      setRestoreError(
        e instanceof Error ? `${e.message} Paste the recovery key again to retry.` : "Could not start the restore",
      );
    } finally {
      setRestoreSubmitting(false);
    }
  };

  const startRehydrate = async () => {
    setRehydrateConfirm(false);
    setRehydrateStarting(true);
    try {
      await api.post("/dr/rehydrate", {});
      flash("Restore of sites and databases started.", "success");
      setRehydrateTrack(true);
      void fetchRestore();
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 409) setRehydrateTrack(true);
      flash(e instanceof Error ? e.message : "Could not start the restore of sites and databases", "error");
    } finally {
      setRehydrateStarting(false);
    }
  };

  const cancelRehydrate = useCallback(() => setRehydrateConfirm(false), []);

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
  const rehydrateBusy = rehydrateTrack || !!restore?.rehydrate_running;
  const restoreBusy = !!restoreTrack || rehydrateBusy;
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
      {/* Install ID */}
      {status.install_id && (
        <div className="bg-dark-900 border border-dark-700 rounded-lg px-3 py-2 mb-3 text-xs">
          <div className="text-dark-400 mb-1">Install ID</div>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="font-mono text-dark-100 break-all select-all">{status.install_id}</span>
            <button onClick={() => void copyInstallId()} className={SMALL_BTN}>
              {idCopied ? "Copied" : "Copy"}
            </button>
          </div>
          <div className="text-dark-400 mt-1">
            Write it down with your recovery key: restoring on a new server asks for it.
          </div>
        </div>
      )}
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
                <th className="px-2 py-1.5 font-normal" />
              </tr>
            </thead>
            <tbody>
              {status.remote_snapshots.map(r => {
                const badge = r.deleted_at
                  ? { label: "Pruned", cls: "bg-dark-700 text-dark-400 border-dark-600" }
                  : r.status === "failed"
                  ? { label: "Upload failed", cls: "bg-danger-500/10 text-danger-400 border-danger-500/20" }
                  : { label: "Uploaded", cls: "bg-rust-500/10 text-rust-400 border-rust-500/20" };
                const restorable = r.status === "uploaded" && r.deleted_at === null;
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
                    <td className="px-2 py-1.5">
                      {restorable && (
                        <div className="flex flex-wrap justify-end gap-1">
                          <button
                            onClick={() => void downloadRemote(r)}
                            disabled={downloadingId === r.id}
                            className={SMALL_BTN}
                          >
                            {downloadingId === r.id ? "Downloading..." : "Download encrypted archive"}
                          </button>
                          <button
                            onClick={() => openRestore(r)}
                            disabled={restoreBusy}
                            className={SMALL_BTN}
                          >
                            Restore from remote snapshot
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Remote restore */}
      <div className="mt-4 pt-3 border-t border-dark-700">
        <div className="text-sm text-dark-200 mb-2">Remote restore</div>
        <RemoteRestoreReport
          data={restore}
          following={!!restoreTrack}
          unreachable={restoreUnreachable}
          timedOut={restoreTimedOut}
        />
        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-dark-400">
            For every site and database whose latest backup is on a remote destination, download it and restore
            it. Run this after restoring the panel on a new server.
          </span>
          <button
            onClick={() => setRehydrateConfirm(true)}
            disabled={rehydrateStarting || rehydrateBusy || !!restoreTrack}
            className="px-3 py-1.5 bg-dark-700 text-dark-300 hover:bg-dark-600 hover:text-dark-100 border border-dark-500 rounded-lg text-xs transition-colors disabled:opacity-50"
          >
            {rehydrateBusy ? "Restoring..." : rehydrateStarting ? "Starting..." : "Restore sites and databases from remote backups"}
          </button>
        </div>
      </div>
      {rehydrateConfirm && (
        <ConfirmDialog
          label={
            "Restore every site and database whose latest backup is on a remote destination?\n" +
            "Their current files and data are replaced by the backup."
          }
          confirmLabel="Restore"
          tone="warn"
          onConfirm={() => void startRehydrate()}
          onCancel={cancelRehydrate}
        />
      )}

      {/* Restore from a remote snapshot. */}
      {restoreTarget &&
        createPortal(
          <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4 dp-modal-overlay">
            <div
              role="alertdialog"
              aria-modal="true"
              aria-label="Restore from remote snapshot"
              className="bg-dark-800 rounded-lg shadow-xl p-6 w-full max-w-xl dp-modal"
            >
              <h3 className="text-sm font-medium text-dark-100 mb-2">Restore from remote snapshot</h3>
              <div className="text-xs text-dark-400 mb-3">
                <div>
                  File: <span className="font-mono text-dark-200 break-all">{restoreTarget.filename}</span>
                </div>
                <div>
                  Panel version: <span className="font-mono text-dark-200">{restoreTarget.from_version}</span>
                  {" "}(the installed panel must be the same version)
                </div>
                <div>
                  Key: <span className="font-mono text-dark-200 break-all">{restoreTarget.recipient_fingerprint}</span>
                </div>
              </div>
              <div className="mb-3 px-3 py-2 rounded-lg text-xs border bg-warn-500/10 text-warn-400 border-warn-500/20">
                The panel database and /etc/dockpanel are replaced by the ones in this snapshot. The panel stops
                and restarts during the restore, and sessions may be signed out.
              </div>
              <label htmlFor="dr-restore-identity" className="block text-xs text-dark-300 mb-1">
                Paste your recovery key. It is used for this restore only and is never stored.
              </label>
              <textarea
                id="dr-restore-identity"
                value={recoveryIdentity}
                onChange={e => setRecoveryIdentity(e.target.value)}
                rows={4}
                spellCheck={false}
                autoComplete="off"
                autoCorrect="off"
                autoCapitalize="off"
                disabled={restoreSubmitting}
                className="w-full bg-dark-900 border border-dark-600 text-dark-100 text-xs rounded-lg px-3 py-2 font-mono mb-3 resize-none"
              />
              {restoreError && (
                <div role="alert" className="mb-3 px-3 py-2 rounded-lg text-xs border break-words bg-danger-500/10 text-danger-400 border-danger-500/20">
                  {restoreError}
                </div>
              )}
              <label className="flex items-center gap-2 text-xs text-dark-200 mb-4">
                <input
                  type="checkbox"
                  checked={restoreAck}
                  onChange={e => setRestoreAck(e.target.checked)}
                  disabled={restoreSubmitting}
                  className="rounded bg-dark-900 border-dark-600"
                />
                I understand that the panel is replaced by this snapshot and restarts
              </label>
              <div className="flex justify-end gap-2">
                <button
                  onClick={closeRestore}
                  disabled={restoreSubmitting}
                  className="px-4 py-2 bg-dark-600 text-dark-200 text-xs font-bold uppercase tracking-wider rounded hover:bg-dark-500 transition-colors disabled:opacity-50"
                >
                  Cancel
                </button>
                <button
                  onClick={() => void submitRestore()}
                  disabled={restoreSubmitting || !restoreAck || !recoveryIdentity.trim()}
                  className="px-4 py-2 bg-danger-500 hover:bg-danger-600 text-white text-xs font-bold uppercase tracking-wider rounded transition-colors disabled:opacity-50"
                >
                  {restoreSubmitting ? "Starting..." : "Restore"}
                </button>
              </div>
            </div>
          </div>,
          document.body,
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
