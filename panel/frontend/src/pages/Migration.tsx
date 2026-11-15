import { useAuth } from "../context/AuthContext";
import { Link, Navigate } from "react-router-dom";
import { useState, useEffect, useRef, useCallback } from "react";
import { api, ApiError } from "../api";

// Inventory as the agent reports it (05-import-hestia W1-A). Every HestiaCP
// field is optional: cPanel and Plesk inventories only carry the first ones.
// It never contains a password, hash or key, and neither does this page.
interface SiteSsl {
  present: boolean;
  issuer?: string | null;
  not_after?: string | null;
  covers?: string[];
  expired?: boolean;
}

interface MigrationSite {
  domain: string;
  doc_root: string;
  size_bytes: number;
  runtime: string;
  file_count: number;
  web_server?: string;
  php_version?: string | null;
  php_version_source?: string | null;
  aliases?: string[];
  canonical_host?: string | null;
  ssl?: SiteSsl | null;
  force_ssl?: boolean;
  hsts?: boolean;
  ftp_user?: string | null;
  suspended?: boolean;
  custom_nginx_template?: string | null;
  paths_to_fix?: { file: string; occurrences: number }[];
  upload_php_files?: number;
}

interface MigrationDb {
  name: string;
  file: string;
  size_bytes: number;
  engine: string;
  db_user?: string;
  suggested_site?: string | null;
  suggested_via?: string | null;
}

interface MigrationMailDomain {
  domain: string;
  accounts: number;
  aliases: number;
  dkim?: boolean;
  maildir_bytes?: number;
}

interface MigrationMail {
  email: string;
  domain: string;
  hash_scheme?: string | null;
  forward_to?: string | null;
  suspended?: boolean;
}

interface DiskCheck {
  staging_free?: number;
  www_free?: number;
  www_needed_estimate?: number;
  ok?: boolean;
  reason?: string | null;
}

interface Inventory {
  id: string;
  source: string;
  sites: MigrationSite[];
  databases: MigrationDb[];
  mail_accounts: MigrationMail[];
  mail_domains?: MigrationMailDomain[];
  ftp_accounts?: { user: string; domain: string; hash_scheme?: string }[];
  disk?: DiskCheck;
  hestia_user?: string;
  warnings: string[];
}

interface MigrationRecord {
  id: string;
  source: string;
  status: string;
  server_id: string | null;
  backup_path: string;
  inventory: Inventory | null;
  result: Record<string, unknown> | null;
  created_at: string;
}

interface ProgressStep {
  step: string;
  label: string;
  status: string;
  message?: string;
}

interface ReportItem {
  kind: string;
  key: string;
  status: string;
  message: string;
  details: Record<string, unknown>;
  attempts: number;
  updated_at: string;
}

interface Report {
  status: string;
  summary: Record<string, number>;
  items: ReportItem[];
  manual_actions: string[];
}

interface Preflight {
  mariadb_local: { installed: boolean; running: boolean; version: string | null; reachable: boolean };
  mail: { installed: boolean; schemes: string[] };
  php: { installed: string[]; missing_for_selection: string[]; legacy: string[] };
  apache: { installed: boolean };
  disk: DiskCheck;
}

interface SiteOptions {
  ssl: boolean;
  aliases: boolean;
  canonical: boolean;
  sftp: boolean;
  force_ssl: boolean;
  hsts: boolean;
}

interface SiteChoice {
  php_version: string; // "" = archive's version, else the wizard default
  options: SiteOptions;
}

// Same list as the panel's `PHP_VERSIONS`; the server validates anyway.
const PHP_CHOICES = ["5.6", "7.4", "8.1", "8.2", "8.3", "8.4", "8.5"];
const LEGACY_PHP = ["5.6", "7.4"];
const KIND_LABEL: Record<string, string> = {
  preflight: "Check",
  site: "Site",
  php: "PHP",
  files: "Files",
  ssl: "Certificate",
  sftp: "SFTP",
  db: "Database",
  mail_domain: "Mail domain",
  mailbox: "Mailbox",
  mail_alias: "Mail alias",
  maildir: "Messages",
};
const FINISHED = ["done", "warning"];
const FORCE_PHRASE = "overwrite";

const fmtElapsed = (s: number) =>
  s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;

const fmtSize = (b: number) => {
  if (b > 1e9) return `${(b / 1e9).toFixed(1)} GB`;
  if (b > 1e6) return `${(b / 1e6).toFixed(1)} MB`;
  if (b > 1e3) return `${(b / 1e3).toFixed(0)} KB`;
  return `${b} B`;
};

const fmtDate = (s?: string | null) => (s ? new Date(s).toLocaleDateString() : "");

const defaultChoice = (s: MigrationSite): SiteChoice => ({
  php_version: "",
  options: {
    ssl: !!s.ssl?.present && !s.ssl?.expired,
    aliases: true,
    canonical: true,
    sftp: !!s.ftp_user,
    force_ssl: s.force_ssl ?? true,
    hsts: s.hsts ?? true,
  },
});

function StatusIcon({ status }: { status: string }) {
  if (status === "in_progress" || status === "running")
    return <div className="w-4 h-4 border-2 border-rust-500 border-t-transparent rounded-full animate-spin shrink-0" />;
  if (status === "done")
    return (
      <svg className="w-4 h-4 text-rust-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
      </svg>
    );
  if (status === "error" || status === "failed")
    return (
      <svg className="w-4 h-4 text-danger-500 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
      </svg>
    );
  if (status === "warning" || status === "skipped")
    return (
      <svg className={`w-4 h-4 shrink-0 ${status === "warning" ? "text-warn-500" : "text-dark-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
      </svg>
    );
  return <div className="w-4 h-4 rounded-full border-2 border-dark-500 shrink-0" />;
}

const statusText = (s: string) =>
  s === "failed" || s === "error" ? "text-danger-400" : s === "warning" ? "text-warn-400" : s === "skipped" ? "text-dark-400" : "text-dark-100";

export default function Migration() {
  const { user } = useAuth();
  // Every hook sits above the admin redirect: a conditional return before an
  // effect makes the hook count differ between renders.
  const [step, setStep] = useState<1 | 2 | 3 | 4>(1);
  const [source, setSource] = useState("auto");
  const [inputMode, setInputMode] = useState<"path" | "url">("path");
  const [backupPath, setBackupPath] = useState("");
  const [backupUrl, setBackupUrl] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [error, setError] = useState("");
  const [migration, setMigration] = useState<MigrationRecord | null>(null);
  const [selectedSites, setSelectedSites] = useState<Set<string>>(new Set());
  const [selectedDbs, setSelectedDbs] = useState<Set<string>>(new Set());
  const [selectedMail, setSelectedMail] = useState<Set<string>>(new Set());
  const [siteChoices, setSiteChoices] = useState<Record<string, SiteChoice>>({});
  const [defaultPhp, setDefaultPhp] = useState("8.3");
  // Which site each selected database belongs to. Prefilled from the analysis'
  // suggestion; a database without a site is refused by the server.
  const [dbSites, setDbSites] = useState<Record<string, string>>({});
  const [preflight, setPreflight] = useState<Preflight | null>(null);
  const [preflightBusy, setPreflightBusy] = useState(false);
  const [installNote, setInstallNote] = useState("");
  // Live overlay from the SSE stream, keyed by "<kind>:<key>". The durable
  // truth is the report (ledger), polled while the import runs.
  const [live, setLive] = useState<Record<string, ProgressStep>>({});
  const [report, setReport] = useState<Report | null>(null);
  const [watchingId, setWatchingId] = useState<string | null>(null);
  const [forceTarget, setForceTarget] = useState<ReportItem | null>(null);
  const [forceText, setForceText] = useState("");
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [startedAt, setStartedAt] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [resumed, setResumed] = useState(false);
  const eventSourceRef = useRef<EventSource | null>(null);
  // The mount fetch and the Analyze button both want to own `analyzingId`; a
  // ref, so the resume callback sees a click made after it began.
  const startedHere = useRef(false);

  const inv = migration?.inventory ?? null;
  const isHestia = inv?.source === "hestiacp";

  const settleAnalysis = (rec: MigrationRecord) => {
    setMigration(rec);
    setAnalyzingId(null);
    setAnalyzing(false);
    if (rec.status === "failed" && !rec.inventory) {
      const reason = (rec.result as { error?: string } | null)?.error;
      setError(reason || "Analysis failed");
      return;
    }
    if (rec.inventory) {
      const i = rec.inventory;
      setSelectedSites(new Set(i.sites.map((s) => s.domain)));
      setSelectedDbs(new Set(i.databases.map((d) => d.name)));
      setSelectedMail(new Set((i.mail_domains ?? []).map((m) => m.domain)));
      setSiteChoices(Object.fromEntries(i.sites.map((s) => [s.domain, defaultChoice(s)])));
      const domains = new Set(i.sites.map((s) => s.domain));
      setDbSites(
        Object.fromEntries(
          i.databases
            .filter((d) => d.suggested_site && domains.has(d.suggested_site))
            .map((d) => [d.name, d.suggested_site as string]),
        ),
      );
    }
    setStep(2);
  };

  // Step 1: Analyze - accepted (202), then polled. The verdict lives in the
  // row, so a reload or a closed tab loses nothing.
  const handleAnalyze = async () => {
    const trimmedPath = backupPath.trim();
    const trimmedUrl = backupUrl.trim();
    if (inputMode === "path" ? !trimmedPath : !trimmedUrl) return;
    startedHere.current = true;
    setError("");
    setAnalyzing(true);
    setResumed(false);
    setStartedAt(Date.now());
    setElapsed(0);
    try {
      const res = await api.post<MigrationRecord>("/migration/analyze", {
        ...(inputMode === "path" ? { path: trimmedPath } : { url: trimmedUrl }),
        source,
      });
      if (res.status === "analyzing") {
        setMigration(res);
        setAnalyzingId(res.id);
      } else {
        settleAnalysis(res);
      }
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Analysis failed");
      setAnalyzing(false);
    }
  };

  useEffect(() => {
    if (!analyzingId) return;
    let stopped = false;
    const ticker = window.setInterval(() => setElapsed(Math.floor((Date.now() - startedAt) / 1000)), 1000);
    const poller = window.setInterval(async () => {
      try {
        const rec = await api.get<MigrationRecord>(`/migration/${analyzingId}`);
        if (!stopped && rec.status !== "analyzing") settleAnalysis(rec);
      } catch (e) {
        // A transient failure is not an answer; a 404 or 403 is.
        if (e instanceof ApiError && (e.status === 403 || e.status === 404)) {
          setAnalyzingId(null);
          setAnalyzing(false);
          setError(e.status === 404 ? "This analysis is no longer on the server. Start it again." : e.message);
        }
      }
    }, 3000);
    return () => {
      stopped = true;
      window.clearInterval(ticker);
      window.clearInterval(poller);
    };
  }, [analyzingId, startedAt]);

  // ── import watching: SSE overlay + durable report polling ──────────────
  const loadReport = useCallback(async (id: string) => {
    try {
      const r = await api.get<Report>(`/migration/${id}/report`);
      setReport(r);
      return r;
    } catch {
      return null;
    }
  }, []);

  const openStream = useCallback((id: string) => {
    eventSourceRef.current?.close();
    const es = new EventSource(`/api/migration/${id}/progress`);
    eventSourceRef.current = es;
    es.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data) as ProgressStep;
        setLive((prev) => ({ ...prev, [data.step]: data }));
      } catch {
        /* keep-alive or malformed line */
      }
    };
    // The stream is an overlay: when it drops (end of run, panel restart), the
    // report poll below carries on and decides when the run is over.
    es.onerror = () => es.close();
  }, []);

  useEffect(() => {
    if (!watchingId) return;
    let stopped = false;
    openStream(watchingId);
    loadReport(watchingId);
    const poller = window.setInterval(async () => {
      try {
        const rec = await api.get<MigrationRecord>(`/migration/${watchingId}`);
        if (stopped) return;
        await loadReport(watchingId);
        if (rec.status !== "importing") {
          setMigration(rec);
          setWatchingId(null);
          setStep(4);
        }
      } catch (e) {
        if (e instanceof ApiError && (e.status === 403 || e.status === 404)) {
          setWatchingId(null);
          setError(e.message);
        }
      }
    }, 5000);
    return () => {
      stopped = true;
      window.clearInterval(poller);
      eventSourceRef.current?.close();
    };
  }, [watchingId, openStream, loadReport]);

  // Pick an analysis or an import back up after a reload.
  const isAdmin = user?.role === "admin";
  useEffect(() => {
    if (!isAdmin) return;
    (async () => {
      try {
        const recent = await api.get<MigrationRecord[]>("/migration");
        // Scoped to the server the operator is looking at.
        const activeServer = localStorage.getItem("dp-active-server");
        const onThisServer = (m: MigrationRecord) => !activeServer || !m.server_id || m.server_id === activeServer;
        if (startedHere.current) return;
        const importing = recent.find((m) => m.status === "importing" && onThisServer(m));
        if (importing) {
          setMigration(importing);
          setStep(3);
          setWatchingId(importing.id);
          return;
        }
        const live = recent.find((m) => m.status === "analyzing" && onThisServer(m));
        if (!live) return;
        setBackupPath(live.backup_path);
        setSource(live.source);
        setMigration(live);
        setResumed(true);
        setAnalyzing(true);
        setStartedAt(new Date(live.created_at).getTime());
        setElapsed(Math.floor((Date.now() - new Date(live.created_at).getTime()) / 1000));
        setAnalyzingId(live.id);
      } catch {
        /* nothing to resume is the normal case */
      }
    })();
  }, [isAdmin]);

  useEffect(() => () => eventSourceRef.current?.close(), []);

  // ── preflight ───────────────────────────────────────────────────────────
  const phpWanted = (() => {
    if (!inv) return [] as string[];
    const out = new Set<string>();
    for (const s of inv.sites) {
      if (!selectedSites.has(s.domain) || s.runtime !== "php") continue;
      const v = siteChoices[s.domain]?.php_version || s.php_version || defaultPhp;
      if (v) out.add(v);
    }
    return Array.from(out).sort();
  })();
  const phpKey = phpWanted.join(",");

  const loadPreflight = useCallback(async () => {
    if (!migration?.id || !migration.inventory) return;
    setPreflightBusy(true);
    try {
      setPreflight(
        await api.get<Preflight>(`/migration/${migration.id}/preflight?php=${encodeURIComponent(phpKey)}`),
      );
    } catch {
      setPreflight(null);
    } finally {
      setPreflightBusy(false);
    }
  }, [migration?.id, migration?.inventory, phpKey]);

  useEffect(() => {
    if (step === 2) loadPreflight();
  }, [step, loadPreflight]);

  const installPhp = async (version: string) => {
    setInstallNote("");
    try {
      await api.post("/php/install", { version });
      setInstallNote(`PHP ${version} is being installed. This takes a few minutes; refresh the checks afterwards. The import also installs a missing version by itself.`);
    } catch (e) {
      setInstallNote(e instanceof ApiError ? e.message : `Could not start the PHP ${version} install`);
    }
  };

  const installLocalDb = async () => {
    setInstallNote("");
    try {
      await api.post("/databases/local/install", {});
      setInstallNote("The local MariaDB server is being installed. Refresh the checks in a few minutes.");
    } catch (e) {
      setInstallNote(e instanceof ApiError ? e.message : "Could not start the MariaDB install");
    }
  };

  // ── selection helpers ───────────────────────────────────────────────────
  const selectedSiteDomains = inv ? inv.sites.filter((s) => selectedSites.has(s.domain)).map((s) => s.domain) : [];
  const siteForDb = (name: string) =>
    dbSites[name] || (selectedSiteDomains.length === 1 ? selectedSiteDomains[0] : "");
  const dbsWithoutSite = Array.from(selectedDbs).filter((n) => !siteForDb(n));
  const setChoice = (domain: string, patch: Partial<SiteChoice>) =>
    setSiteChoices((prev) => ({ ...prev, [domain]: { ...prev[domain], ...patch } }));
  const setOption = (domain: string, key: keyof SiteOptions, value: boolean) =>
    setSiteChoices((prev) => ({
      ...prev,
      [domain]: { ...prev[domain], options: { ...prev[domain].options, [key]: value } },
    }));
  const toggle = (set: Set<string>, value: string, on: boolean) => {
    const next = new Set(set);
    if (on) next.add(value);
    else next.delete(value);
    return next;
  };
  const sitesNeedingPhp = inv
    ? inv.sites.filter(
        (s) => selectedSites.has(s.domain) && s.runtime === "php" && !s.php_version && !siteChoices[s.domain]?.php_version && !defaultPhp,
      )
    : [];
  const selectionCount = selectedSites.size + selectedDbs.size + selectedMail.size;
  const diskBlocked = isHestia && inv?.disk?.ok === false;

  // ── import (first run, retry, force) ────────────────────────────────────
  const startImport = async (body: Record<string, unknown>) => {
    if (!migration) return;
    setError("");
    setLive({});
    setReport(null);
    try {
      await api.post(`/migration/${migration.id}/import`, body);
      setStep(3);
      setWatchingId(migration.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Import failed");
    }
  };

  const handleImport = () => {
    if (!inv) return;
    startImport({
      default_php_version: defaultPhp || undefined,
      sites: inv.sites
        .filter((s) => selectedSites.has(s.domain))
        .map((s) => {
          const c = siteChoices[s.domain] ?? defaultChoice(s);
          return {
            domain: s.domain,
            php_version: c.php_version || undefined,
            options: c.options,
          };
        }),
      databases: inv.databases
        .filter((d) => selectedDbs.has(d.name))
        .map((d) => ({ name: d.name, site_domain: siteForDb(d.name) || undefined })),
      mail_domains: Array.from(selectedMail),
    });
  };

  const handleRetry = () => startImport({ retry: true });

  const confirmForce = () => {
    if (!forceTarget || forceText.trim().toLowerCase() !== FORCE_PHRASE) return;
    const ref = `${forceTarget.kind}:${forceTarget.key}`;
    setForceTarget(null);
    setForceText("");
    startImport({ retry: true, force_items: [ref] });
  };

  if (!isAdmin) return <Navigate to="/" replace />;

  const summary = report?.summary ?? {};
  const items = (report?.items ?? []).filter((i) => i.kind !== "preflight" || i.status !== "done");
  const failedCount = summary.failed ?? 0;

  const itemRow = (it: ReportItem, withActions: boolean) => {
    const ref = `${it.kind}:${it.key}`;
    const ev = live[ref];
    const running = it.status === "running" || ev?.status === "in_progress";
    const status = running ? "in_progress" : it.status;
    const message = running && ev?.message ? ev.message : it.message;
    return (
      <div key={ref} className="flex items-start gap-3 py-1.5 border-b border-dark-700/60 last:border-0">
        <div className="pt-0.5"><StatusIcon status={status} /></div>
        <div className="w-24 shrink-0 text-xs text-dark-400 pt-0.5">{KIND_LABEL[it.kind] ?? it.kind}</div>
        <div className="flex-1 min-w-0">
          <div className={`text-sm font-mono break-all ${statusText(status)}`}>{it.key}</div>
          {message && <div className="text-xs text-dark-300 mt-0.5 break-words">{message}</div>}
        </div>
        {it.attempts > 1 && <span className="text-xs text-dark-500 pt-0.5">{it.attempts} attempts</span>}
        {withActions && FINISHED.includes(it.status) && it.kind !== "preflight" && it.kind !== "php" && (
          <button
            onClick={() => { setForceTarget(it); setForceText(""); }}
            className="text-xs text-dark-300 hover:text-rust-400 underline shrink-0"
          >
            Force re-import
          </button>
        )}
      </div>
    );
  };

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-50 font-mono">Migration Wizard</h1>
        <p className="text-sm text-dark-300 mt-1">
          Import sites and databases from cPanel, Plesk, or HestiaCP. A HestiaCP user backup also brings its certificates,
          FTP accounts (as SFTP) and mail, with the same passwords.
        </p>
      </div>

      <div className="flex items-center gap-2 text-xs font-mono">
        {[1, 2, 3, 4].map((s) => (
          <div key={s} className={`flex items-center gap-1 ${step >= s ? "text-rust-400" : "text-dark-400"}`}>
            <div className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold ${step >= s ? "bg-rust-500 text-dark-950" : "bg-dark-700 text-dark-400"}`}>{s}</div>
            <span className="hidden sm:inline">{["Source", "Review", "Import", "Report"][s - 1]}</span>
            {s < 4 && <span className="text-dark-600 mx-1">-</span>}
          </div>
        ))}
      </div>

      {error && (
        <div className="px-4 py-3 bg-danger-500/10 border border-danger-500/30 rounded-lg text-sm text-danger-400">{error}</div>
      )}

      {/* Step 1: Source + Path */}
      {step === 1 && (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-6 space-y-5">
          <h2 className="text-lg font-bold text-dark-50 font-mono">Select Backup Source</h2>

          <div className="flex gap-3 flex-wrap">
            {[
              { id: "auto", label: "Auto-detect", desc: "Recognise the panel from the archive" },
              { id: "cpanel", label: "cPanel", desc: "Full backup (.tar.gz)" },
              { id: "plesk", label: "Plesk", desc: "Domain backup" },
              { id: "hestiacp", label: "HestiaCP", desc: "User backup (.tar)" },
            ].map((s) => (
              <button
                key={s.id}
                onClick={() => setSource(s.id)}
                className={`flex-1 min-w-[10rem] p-4 rounded-lg border text-left transition-colors ${source === s.id ? "border-rust-500 bg-rust-500/10" : "border-dark-600 bg-dark-900 hover:border-dark-400"}`}
              >
                <div className={`text-sm font-bold ${source === s.id ? "text-rust-400" : "text-dark-200"}`}>{s.label}</div>
                <div className="text-xs text-dark-400 mt-1">{s.desc}</div>
              </button>
            ))}
          </div>

          <div>
            <div className="flex gap-2 mb-3">
              {([
                { id: "path" as const, label: "Path on server" },
                { id: "url" as const, label: "Fetch from URL" },
              ]).map((m) => (
                <button
                  key={m.id}
                  onClick={() => setInputMode(m.id)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-colors ${inputMode === m.id ? "bg-rust-500 text-dark-950" : "bg-dark-900 text-dark-300 border border-dark-600 hover:border-dark-400"}`}
                >
                  {m.label}
                </button>
              ))}
            </div>

            {inputMode === "path" ? (
              <>
                <label className="block text-sm text-dark-200 mb-1">Backup File Path</label>
                <input
                  value={backupPath}
                  onChange={(e) => setBackupPath(e.target.value)}
                  placeholder="/var/backups/user.2026-01-01_00-00-00.tar"
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-50 text-sm focus:border-rust-500 focus:outline-none font-mono"
                />
                <p className="text-xs text-dark-400 mt-1">
                  Upload the backup to your server via SFTP first, then enter the full path here.
                  It must be under <code className="text-dark-200">/var/backups/</code>.{" "}
                  <code className="text-dark-200">/tmp/</code> will not work: the agent runs with
                  a private <code className="text-dark-200">/tmp</code> and cannot see the host's.
                  Leave the archive in place until the import is finished.
                </p>
              </>
            ) : (
              <>
                <label className="block text-sm text-dark-200 mb-1">Backup URL</label>
                <input
                  value={backupUrl}
                  onChange={(e) => setBackupUrl(e.target.value)}
                  placeholder="https://example.com/backup.tar.gz"
                  className="w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-50 text-sm focus:border-rust-500 focus:outline-none font-mono"
                />
                <p className="text-xs text-dark-400 mt-1">
                  The server downloads the archive itself - no SFTP step needed. HTTP(S) only, and
                  the URL must not resolve to an internal or private address.
                </p>
              </>
            )}
          </div>

          <button
            onClick={handleAnalyze}
            disabled={(inputMode === "path" ? !backupPath.trim() : !backupUrl.trim()) || analyzing}
            className="px-5 py-2.5 bg-rust-500 text-dark-950 rounded-lg text-sm font-bold hover:bg-rust-400 transition-colors disabled:opacity-50"
          >
            {analyzing ? "Analyzing..." : "Analyze Backup"}
          </button>

          {analyzing && (
            <div className="flex items-start gap-3 px-4 py-3 bg-dark-900 border border-dark-600 rounded-lg">
              <StatusIcon status="in_progress" />
              <div className="text-sm">
                <p className="text-dark-100">
                  {resumed ? "Picking up an analysis that was already running on the server." : "Reading the archive."}{" "}
                  <span className="font-mono text-dark-200">{fmtElapsed(elapsed)}</span>
                </p>
                <p className="text-xs text-dark-400 mt-1">
                  A large account takes minutes. This runs on the server, not in this tab - you can leave the page and
                  come back, and closing the browser will not stop it.
                </p>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Step 2: Review */}
      {step === 2 && inv && (
        <div className="space-y-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
            <h2 className="text-lg font-bold text-dark-50 font-mono mb-1">Analysis Results</h2>
            <p className="text-sm text-dark-300">
              {inv.source}{inv.hestia_user ? ` (${inv.hestia_user})` : ""}: {inv.sites.length} site{inv.sites.length !== 1 ? "s" : ""},{" "}
              {inv.databases.length} database{inv.databases.length !== 1 ? "s" : ""},{" "}
              {(inv.mail_domains ?? []).length > 0 ? `${inv.mail_domains!.length} mail domain(s), ` : ""}
              {inv.mail_accounts.length} email account{inv.mail_accounts.length !== 1 ? "s" : ""}
            </p>
          </div>

          {/* Disk */}
          {inv.disk && (
            <div className={`px-4 py-3 rounded-lg border text-sm ${inv.disk.ok === false ? "bg-danger-500/10 border-danger-500/30 text-danger-400" : "bg-dark-800 border-dark-600 text-dark-300"}`}>
              {inv.disk.ok === false ? (
                <>Not enough disk space: {inv.disk.reason || "free some space and analyse again"}. The import is refused until then.</>
              ) : (
                <>
                  Disk: {inv.disk.www_free != null ? `${fmtSize(inv.disk.www_free)} free for sites` : "checked"}
                  {inv.disk.www_needed_estimate ? `, about ${fmtSize(inv.disk.www_needed_estimate)} needed` : ""}.
                </>
              )}
            </div>
          )}

          {inv.warnings.length > 0 && (
            <div className="px-4 py-3 bg-warn-500/10 border border-warn-500/30 rounded-lg space-y-1">
              {inv.warnings.map((w, i) => (
                <p key={i} className="text-sm text-warn-400">{w}</p>
              ))}
            </div>
          )}

          {/* Preflight */}
          {isHestia && (
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-5 space-y-2">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-dark-50 font-mono uppercase tracking-wider">Server checks</h3>
                <button onClick={loadPreflight} disabled={preflightBusy} className="text-xs text-dark-300 hover:text-rust-400 underline disabled:opacity-50">
                  {preflightBusy ? "Checking..." : "Refresh checks"}
                </button>
              </div>
              {!preflight && !preflightBusy && <p className="text-xs text-dark-400">The server could not be asked.</p>}
              {preflight && (
                <div className="space-y-1.5 text-sm">
                  {selectedDbs.size > 0 && (
                    <div className="flex items-center gap-2">
                      <StatusIcon status={preflight.mariadb_local.installed && preflight.mariadb_local.running ? "done" : "failed"} />
                      <span className="text-dark-100">
                        Local MariaDB server{preflight.mariadb_local.version ? ` ${preflight.mariadb_local.version}` : ""}
                        {!preflight.mariadb_local.installed ? ": not installed" : !preflight.mariadb_local.running ? ": not running" : ""}
                      </span>
                      {!preflight.mariadb_local.installed && (
                        <button onClick={installLocalDb} className="ml-auto text-xs px-2 py-1 bg-dark-700 rounded hover:bg-dark-600 text-dark-100">Install</button>
                      )}
                    </div>
                  )}
                  {selectedMail.size > 0 && (
                    <div className="flex items-center gap-2">
                      <StatusIcon status={preflight.mail.installed ? "done" : "failed"} />
                      <span className="text-dark-100">Mail server{preflight.mail.installed ? "" : ": not installed"}</span>
                      {!preflight.mail.installed && (
                        <Link to="/mail" className="ml-auto text-xs px-2 py-1 bg-dark-700 rounded hover:bg-dark-600 text-dark-100">Open Mail</Link>
                      )}
                    </div>
                  )}
                  {phpWanted.length > 0 && (
                    <div className="flex items-start gap-2">
                      <StatusIcon status={preflight.php.missing_for_selection.length === 0 ? "done" : "warning"} />
                      <div className="flex-1">
                        <span className="text-dark-100">PHP {phpWanted.join(", ")}</span>
                        {preflight.php.missing_for_selection.length > 0 && (
                          <span className="text-dark-300">: missing {preflight.php.missing_for_selection.join(", ")} (installed by the import if needed)</span>
                        )}
                        {preflight.php.legacy.length > 0 && (
                          <p className="text-xs text-warn-400">Legacy, no security updates: PHP {preflight.php.legacy.join(", ")}</p>
                        )}
                      </div>
                      <div className="flex gap-1">
                        {preflight.php.missing_for_selection.map((v) => (
                          <button key={v} onClick={() => installPhp(v)} className="text-xs px-2 py-1 bg-dark-700 rounded hover:bg-dark-600 text-dark-100">Install {v}</button>
                        ))}
                      </div>
                    </div>
                  )}
                  {inv.sites.some((s) => selectedSites.has(s.domain) && s.web_server === "apache") && (
                    <div className="flex items-center gap-2">
                      <StatusIcon status={preflight.apache.installed ? "done" : "warning"} />
                      <span className="text-dark-100">
                        Apache{preflight.apache.installed ? "" : ": not installed, Apache sites will be imported in nginx mode (.htaccess not read)"}
                      </span>
                    </div>
                  )}
                </div>
              )}
              {installNote && <p className="text-xs text-dark-300">{installNote}</p>}
            </div>
          )}

          {/* Sites */}
          {inv.sites.length > 0 && (
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
              <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
                <h3 className="text-sm font-bold text-dark-50 font-mono uppercase tracking-wider">Sites ({selectedSites.size}/{inv.sites.length})</h3>
                {isHestia && (
                  <label className="text-xs text-dark-300 flex items-center gap-2">
                    PHP for sites on the HestiaCP default
                    <select value={defaultPhp} onChange={(e) => setDefaultPhp(e.target.value)} className="px-2 py-1 bg-dark-900 border border-dark-500 rounded text-xs text-dark-50 font-mono">
                      {PHP_CHOICES.map((v) => <option key={v} value={v}>{v}{LEGACY_PHP.includes(v) ? " (legacy)" : ""}</option>)}
                    </select>
                  </label>
                )}
              </div>
              <div className="space-y-2">
                {inv.sites.map((s) => {
                  const c = siteChoices[s.domain] ?? defaultChoice(s);
                  const on = selectedSites.has(s.domain);
                  const effectivePhp = c.php_version || s.php_version || defaultPhp;
                  return (
                    <div key={s.domain} className={`p-3 rounded border ${on ? "border-dark-500 bg-dark-900/40" : "border-dark-700"}`}>
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={on}
                          onChange={(e) => setSelectedSites(toggle(selectedSites, s.domain, e.target.checked))}
                          className="w-4 h-4 text-rust-500 border-dark-500 rounded"
                        />
                        <span className="text-sm text-dark-50 font-mono">{s.domain}</span>
                        <span className="text-xs text-dark-400">
                          {s.runtime}{s.web_server ? ` - ${s.web_server}` : ""} - {fmtSize(s.size_bytes)}{s.file_count ? ` - ${s.file_count} files` : ""}
                        </span>
                        {s.suspended && <span className="text-xs text-warn-400">suspended in HestiaCP</span>}
                      </label>
                      {on && isHestia && (
                        <div className="mt-2 ml-7 grid gap-2 text-xs text-dark-300">
                          {s.runtime === "php" && (
                            <div className="flex items-center gap-2 flex-wrap">
                              <span>PHP</span>
                              <select
                                aria-label={`PHP version for ${s.domain}`}
                                value={c.php_version}
                                onChange={(e) => setChoice(s.domain, { php_version: e.target.value })}
                                className="px-2 py-1 bg-dark-900 border border-dark-500 rounded text-xs text-dark-50 font-mono"
                              >
                                <option value="">{s.php_version ? `${s.php_version} (from HestiaCP)` : `default (${defaultPhp})`}</option>
                                {PHP_CHOICES.map((v) => <option key={v} value={v}>{v}</option>)}
                              </select>
                              {LEGACY_PHP.includes(effectivePhp) && (
                                <span className="text-warn-400">Legacy, no security updates</span>
                              )}
                            </div>
                          )}
                          {(s.aliases ?? []).length > 0 && (
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.aliases} onChange={(e) => setOption(s.domain, "aliases", e.target.checked)} />
                              Aliases: <span className="font-mono text-dark-200">{(s.aliases ?? []).join(", ")}</span>
                            </label>
                          )}
                          {s.canonical_host && (
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.canonical} onChange={(e) => setOption(s.domain, "canonical", e.target.checked)} />
                              Redirect to {s.canonical_host === "www" ? `www.${s.domain}` : s.domain}
                            </label>
                          )}
                          {s.ssl?.present && (
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.ssl} disabled={!!s.ssl.expired} onChange={(e) => setOption(s.domain, "ssl", e.target.checked)} />
                              Certificate{s.ssl.issuer ? ` (${s.ssl.issuer})` : ""}
                              {s.ssl.not_after && <span className={s.ssl.expired ? "text-danger-400" : "text-dark-400"}>{s.ssl.expired ? "expired" : "expires"} {fmtDate(s.ssl.not_after)}</span>}
                            </label>
                          )}
                          <div className="flex items-center gap-4">
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.force_ssl} onChange={(e) => setOption(s.domain, "force_ssl", e.target.checked)} />
                              Force SSL
                            </label>
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.hsts} onChange={(e) => setOption(s.domain, "hsts", e.target.checked)} />
                              HSTS
                            </label>
                          </div>
                          {s.ftp_user && (
                            <label className="flex items-center gap-2">
                              <input type="checkbox" checked={c.options.sftp} onChange={(e) => setOption(s.domain, "sftp", e.target.checked)} />
                              SFTP account <span className="font-mono text-dark-200">{s.ftp_user}</span> (HestiaCP FTP password kept)
                            </label>
                          )}
                          {s.custom_nginx_template && (
                            <p className="text-warn-400">Custom nginx template {s.custom_nginx_template}: not translated, saved in private/ for review.</p>
                          )}
                          {(s.paths_to_fix ?? []).length > 0 && (
                            <p className="text-warn-400">
                              Old HestiaCP paths in: {(s.paths_to_fix ?? []).map((p) => `${p.file} (${p.occurrences})`).join(", ")}
                            </p>
                          )}
                          {(s.upload_php_files ?? 0) > 0 && (
                            <p className="text-warn-400">{s.upload_php_files} PHP file(s) in upload folders: they will be blocked from running.</p>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              {sitesNeedingPhp.length > 0 && (
                <p className="text-xs text-warn-400 mt-3">Choose a PHP version for {sitesNeedingPhp.map((s) => s.domain).join(", ")}.</p>
              )}
            </div>
          )}

          {/* Databases */}
          {inv.databases.length > 0 && (
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
              <h3 className="text-sm font-bold text-dark-50 font-mono uppercase tracking-wider mb-3">Databases ({selectedDbs.size}/{inv.databases.length})</h3>
              <div className="space-y-2">
                {inv.databases.map((d) => (
                  <div key={d.name} className="flex items-center gap-3 p-2 rounded hover:bg-dark-700/30 flex-wrap">
                    <input
                      type="checkbox"
                      aria-label={`Import database ${d.name}`}
                      checked={selectedDbs.has(d.name)}
                      onChange={(e) => setSelectedDbs(toggle(selectedDbs, d.name, e.target.checked))}
                      className="w-4 h-4 text-rust-500 border-dark-500 rounded"
                    />
                    <div className="flex-1 min-w-0">
                      <span className="text-sm text-dark-50 font-mono">{d.name}</span>
                      <span className="text-xs text-dark-400 ml-2">
                        {d.engine} - {fmtSize(d.size_bytes)}{d.db_user ? ` - user ${d.db_user}` : ""}
                        {d.suggested_site ? ` - suggested ${d.suggested_site}${d.suggested_via ? ` (${d.suggested_via})` : ""}` : ""}
                      </span>
                    </div>
                    {selectedDbs.has(d.name) && selectedSiteDomains.length > 1 && (
                      <select
                        aria-label={`Site for database ${d.name}`}
                        value={siteForDb(d.name)}
                        onChange={(e) => setDbSites({ ...dbSites, [d.name]: e.target.value })}
                        className="px-2 py-1 bg-dark-900 border border-dark-500 rounded text-xs text-dark-50 font-mono"
                      >
                        <option value="">Choose a site...</option>
                        {selectedSiteDomains.map((dom) => <option key={dom} value={dom}>{dom}</option>)}
                      </select>
                    )}
                  </div>
                ))}
              </div>
              {isHestia && selectedDbs.size > 0 && (
                <p className="text-xs text-dark-400 mt-3">
                  Imported into the server's local MariaDB with their original users and passwords: the sites' configuration files keep working unchanged.
                </p>
              )}
              {selectedDbs.size > 0 && selectedSiteDomains.length === 0 && (
                <p className="text-xs text-warn-400 mt-3">
                  A database has to belong to a site. Select at least one site above, or import the site first and run this again.
                </p>
              )}
            </div>
          )}

          {/* Mail */}
          {isHestia && (inv.mail_domains ?? []).length > 0 ? (
            <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
              <h3 className="text-sm font-bold text-dark-50 font-mono uppercase tracking-wider mb-3">Mail ({selectedMail.size}/{inv.mail_domains!.length})</h3>
              <div className="space-y-3">
                {inv.mail_domains!.map((m) => {
                  const boxes = inv.mail_accounts.filter((a) => a.domain === m.domain);
                  return (
                    <div key={m.domain}>
                      <label className="flex items-center gap-3 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={selectedMail.has(m.domain)}
                          onChange={(e) => setSelectedMail(toggle(selectedMail, m.domain, e.target.checked))}
                          className="w-4 h-4 text-rust-500 border-dark-500 rounded"
                        />
                        <span className="text-sm text-dark-50 font-mono">{m.domain}</span>
                        <span className="text-xs text-dark-400">
                          {m.accounts} mailbox(es), {m.aliases} alias(es){m.dkim ? ", DKIM" : ""}{m.maildir_bytes ? `, ${fmtSize(m.maildir_bytes)}` : ""}
                        </span>
                      </label>
                      {boxes.length > 0 && (
                        <div className="flex flex-wrap gap-2 mt-1.5 ml-7">
                          {boxes.map((b) => {
                            const unsupported = !!(preflight?.mail.installed && b.hash_scheme && preflight.mail.schemes.length > 0 && !preflight.mail.schemes.includes(b.hash_scheme.toUpperCase()));
                            return (
                              <span key={b.email} title={unsupported ? "Password scheme not supported here: the mailbox will be disabled until a new password is set" : undefined} className={`px-2 py-1 rounded text-xs font-mono ${unsupported ? "bg-warn-500/10 text-warn-400" : "bg-dark-700 text-dark-200"}`}>
                                {b.email}{b.forward_to ? " (forward)" : ""}{unsupported ? " (password scheme not supported)" : ""}
                              </span>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
              <p className="text-xs text-dark-400 mt-3">
                No DNS record and no mail certificate are created: switch the MX records once you are ready.
              </p>
            </div>
          ) : (
            inv.mail_accounts.length > 0 && (
              <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
                <h3 className="text-sm font-bold text-dark-50 font-mono uppercase tracking-wider mb-3">Email Accounts ({inv.mail_accounts.length})</h3>
                <p className="text-xs text-dark-400 mb-2">Email accounts from this panel are listed for reference and need to be recreated in the Mail section.</p>
                <div className="flex flex-wrap gap-2">
                  {inv.mail_accounts.map((m) => (
                    <span key={m.email} className="px-2 py-1 bg-dark-700 rounded text-xs text-dark-200 font-mono">{m.email}</span>
                  ))}
                </div>
              </div>
            )
          )}

          <div className="flex gap-3 flex-wrap">
            <button onClick={() => setStep(1)} className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors">
              Back
            </button>
            <button
              onClick={handleImport}
              disabled={selectionCount === 0 || dbsWithoutSite.length > 0 || diskBlocked || sitesNeedingPhp.length > 0}
              title={dbsWithoutSite.length > 0 ? `Choose a site for: ${dbsWithoutSite.join(", ")}` : undefined}
              className="px-5 py-2.5 bg-rust-500 text-dark-950 rounded-lg text-sm font-bold hover:bg-rust-400 transition-colors disabled:opacity-50"
            >
              Import {selectionCount} item{selectionCount !== 1 ? "s" : ""}
            </button>
            {migration && migration.status !== "analyzed" && (
              <button onClick={() => { setStep(4); loadReport(migration.id); }} className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors">
                Previous report
              </button>
            )}
          </div>
          {dbsWithoutSite.length > 0 && (
            <p className="text-xs text-warn-400">Choose a site for {dbsWithoutSite.join(", ")} before importing.</p>
          )}
        </div>
      )}

      {/* Step 3: Progress (per item) */}
      {step === 3 && (
        <div className="bg-dark-800 border border-dark-600 rounded-lg p-5 space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-bold text-dark-50 font-mono">Importing...</h2>
            <span className="text-xs text-dark-400">
              {summary.done ?? 0} done, {summary.warning ?? 0} with warnings, {summary.failed ?? 0} failed
            </span>
          </div>
          <p className="text-xs text-dark-400">
            This runs on the server. You can leave the page: the import continues, and coming back here shows where it is.
          </p>
          <div>
            {items.map((it) => itemRow(it, false))}
            {/* Steps the ledger has not written yet (they appear in the stream first). */}
            {Object.values(live)
              .filter((p) => p.step !== "complete" && !items.some((it) => `${it.kind}:${it.key}` === p.step))
              .map((p) => (
                <div key={p.step} className="flex items-start gap-3 py-1.5">
                  <div className="pt-0.5"><StatusIcon status={p.status} /></div>
                  <div className="flex-1 min-w-0">
                    <div className={`text-sm font-mono ${statusText(p.status)}`}>{p.label}</div>
                    {p.message && <div className="text-xs text-dark-300">{p.message}</div>}
                  </div>
                </div>
              ))}
            {items.length === 0 && Object.keys(live).length === 0 && (
              <div className="flex items-center gap-3">
                <StatusIcon status="in_progress" />
                <span className="text-sm text-dark-300">Starting import...</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Step 4: Report */}
      {step === 4 && (
        <div className="space-y-4">
          <div className="bg-dark-800 border border-dark-600 rounded-lg p-5">
            <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
              <h2 className="text-lg font-bold text-dark-50 font-mono">Import report</h2>
              <span className="text-xs text-dark-300">
                {summary.done ?? 0} done - {summary.warning ?? 0} with warnings - {summary.skipped ?? 0} skipped - {summary.failed ?? 0} failed
                {(summary.pending ?? 0) > 0 ? ` - ${summary.pending} waiting` : ""}
              </span>
            </div>
            {!report && <p className="text-sm text-dark-400">Loading the report...</p>}
            {report && items.length === 0 && <p className="text-sm text-dark-400">Nothing was imported.</p>}
            <div>{items.map((it) => itemRow(it, true))}</div>
          </div>

          {report && report.manual_actions.length > 0 && (
            <div className="bg-warn-500/10 border border-warn-500/30 rounded-lg p-4 space-y-1.5">
              <h3 className="text-sm font-medium text-warn-400">Manual actions</h3>
              {report.manual_actions.map((a, i) => (
                <p key={i} className="text-xs text-dark-200">{a}</p>
              ))}
            </div>
          )}

          {forceTarget && (
            <div className="bg-dark-800 border border-danger-500/40 rounded-lg p-4 space-y-2">
              <p className="text-sm text-dark-100">
                Force re-import of {KIND_LABEL[forceTarget.kind] ?? forceTarget.kind} <span className="font-mono">{forceTarget.key}</span>:
                this overwrites data written since the first import.
              </p>
              <label className="block text-xs text-dark-300">
                Type <span className="font-mono text-dark-100">{FORCE_PHRASE}</span> to confirm
                <input
                  value={forceText}
                  onChange={(e) => setForceText(e.target.value)}
                  className="mt-1 w-full px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-dark-50 text-sm font-mono focus:border-danger-500 focus:outline-none"
                />
              </label>
              <div className="flex gap-2">
                <button
                  onClick={confirmForce}
                  disabled={forceText.trim().toLowerCase() !== FORCE_PHRASE}
                  className="px-4 py-2 bg-danger-500 text-dark-950 rounded-lg text-sm font-bold disabled:opacity-50"
                >
                  Re-import
                </button>
                <button onClick={() => setForceTarget(null)} className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600">Cancel</button>
              </div>
            </div>
          )}

          <div className="flex gap-3 flex-wrap">
            {failedCount + (summary.pending ?? 0) > 0 && (
              <button onClick={handleRetry} className="px-4 py-2 bg-rust-500 text-dark-950 rounded-lg text-sm font-bold hover:bg-rust-400 transition-colors">
                Retry failed
              </button>
            )}
            {inv && (
              <button onClick={() => setStep(2)} className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors">
                Change selection
              </button>
            )}
            {/* `Link`, not `<a href>`: an anchor reloads the whole SPA. */}
            <Link to="/sites" className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors">
              View Sites
            </Link>
            <Link to="/databases" className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors">
              View Databases
            </Link>
            <button
              onClick={() => { setStep(1); setMigration(null); setReport(null); setLive({}); setError(""); startedHere.current = true; }}
              className="px-4 py-2 bg-dark-700 text-dark-200 rounded-lg text-sm hover:bg-dark-600 transition-colors"
            >
              Start New Migration
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
