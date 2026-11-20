import { Fragment, useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useServer } from "../context/ServerContext";
import { api } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import { useVulnSummary, type VulnSummaryTarget } from "../components/VulnBadge";
import { formatDate, timeAgo } from "../utils/format";

/**
 * Page "Vulnerabilities" (conception 13, batch 3): every CVE the scanner found
 * on the sites, Docker images and systems the caller may see. The API filters
 * by role, so the page is open to every account; Accept and Remove exception
 * are admin only, as is the per-server scanner state.
 *
 * Contracts: conception/13-scanner-cve-lot1-contrat.md (read API) and
 * conception/13-scanner-cve-lots2-5-contrat.md (exceptions, group_by=vuln).
 */

const PAGE_SIZE = 100;
const MAX_ACCEPT_DAYS = 90;
const DEFAULT_ACCEPT_DAYS = 30;
const DAY_MS = 86_400_000;

interface VulnPackage {
  package: string;
  version: string;
  fixed_version: string | null;
  location: string | null;
}

interface VulnAccepted {
  reason: string;
  expires_at: string;
  created_by_email: string | null;
}

interface VulnTargetRef {
  id: string;
  kind: string;
  ref: string;
  server_id: string;
  server_name: string;
  site_id: string | null;
  app_name: string | null;
  git_deploy_id: string | null;
  exposed: boolean | null;
}

interface VulnItem {
  id: string;
  target_id: string;
  vuln_id: string;
  aliases: string[];
  package: string;
  version: string;
  pkg_type: string | null;
  location: string | null;
  severity: string;
  cvss: number | null;
  kev: boolean;
  kev_ransomware: boolean;
  epss: number | null;
  epss_percentile: number | null;
  risk: number | null;
  fix_state: string;
  fixed_version: string | null;
  title: string | null;
  url: string | null;
  first_seen: string;
  last_seen: string;
  resolved_at: string | null;
  accepted?: VulnAccepted | null;
  packages?: VulnPackage[];
  target: VulnTargetRef;
}

interface VulnList {
  items: VulnItem[];
  total: number;
}

const SEVERITY_OPTIONS = ["critical", "high", "medium", "low", "unknown"];
const KIND_OPTIONS: { value: string; label: string }[] = [
  { value: "site", label: "Site" },
  { value: "image", label: "Docker image" },
  { value: "system", label: "System" },
];

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-danger-500/15 text-danger-400",
  high: "bg-warn-500/15 text-warn-400",
  medium: "bg-warn-500/10 text-warn-500",
  low: "bg-accent-500/10 text-accent-400",
};

const inputCls = "px-3 py-2 bg-dark-800 border border-dark-500 rounded-lg text-sm text-dark-50";
const btnSecondary =
  "px-3 py-1.5 bg-dark-700 text-dark-200 hover:bg-dark-600 hover:text-dark-100 border border-dark-600 rounded-lg text-xs font-medium disabled:opacity-50 transition-colors";

function capitalize(s: string): string {
  return s ? s[0].toUpperCase() + s.slice(1) : s;
}

/** Advisory link: NVD for a CVE, GitHub for a GHSA, else the scanner's own URL. */
function advisoryUrl(item: Pick<VulnItem, "vuln_id" | "url">): string | null {
  const id = item.vuln_id;
  if (/^CVE-\d{4}-\d+$/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(id.toUpperCase())}`;
  if (/^GHSA-[\w-]+$/i.test(id)) return `https://github.com/advisories/${encodeURIComponent(id)}`;
  if (item.url && /^https?:\/\//i.test(item.url)) return item.url;
  return null;
}

function targetLabel(t: Pick<VulnTargetRef, "kind" | "ref" | "app_name"> & { server_name?: string }): string {
  if (t.kind === "system") return t.server_name ? `System (${t.server_name})` : "System";
  if (t.kind === "image" && t.app_name) return `${t.app_name} (${t.ref})`;
  return t.ref;
}

/** The packages of a row, whether the API grouped by CVE or not. */
function packagesOf(item: VulnItem): VulnPackage[] {
  if (Array.isArray(item.packages) && item.packages.length > 0) return item.packages;
  return [{ package: item.package, version: item.version, fixed_version: item.fixed_version, location: item.location }];
}

function dateInputValue(d: Date): string {
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}-${m}-${day}`;
}

function addDays(days: number): Date {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() + days);
  return d;
}

/**
 * The expiry sent for a picked day: the start of that local day, kept inside
 * `]now, now + 90 days]` so the API never refuses a date the picker offered.
 */
function acceptExpiry(day: string, now = Date.now()): string | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!m) return null;
  const ts = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3]), 0, 0, 0, 0).getTime();
  if (!Number.isFinite(ts) || ts <= now) return null;
  const capped = Math.min(ts, now + MAX_ACCEPT_DAYS * DAY_MS - 60_000);
  return new Date(capped).toISOString();
}

export default function Vulnerabilities() {
  const { user } = useAuth();
  const { servers } = useServer();
  const isAdmin = user?.role === "admin";
  const [params, setParams] = useSearchParams();

  const severity = params.get("severity") ?? "";
  const kevOnly = params.get("kev") === "true";
  const kind = params.get("kind") ?? "";
  const serverId = params.get("server_id") ?? "";
  const targetId = params.get("target_id") ?? "";
  const fixableOnly = params.get("fixable") === "true";
  const showAccepted = params.get("include_accepted") === "true";
  const showResolved = params.get("include_resolved") === "true";
  const groupByCve = params.get("group") !== "none";
  const page = Math.max(0, parseInt(params.get("page") ?? "0", 10) || 0);

  const [refreshKey, setRefreshKey] = useState(0);
  const summaryState = useVulnSummary(true, refreshKey);
  const summary = summaryState.summary;

  const [list, setList] = useState<VulnList | null>(null);
  const [loading, setLoading] = useState(false);
  const [listError, setListError] = useState("");
  const [message, setMessage] = useState<{ text: string; type: "success" | "error" } | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [acceptFor, setAcceptFor] = useState<VulnItem | null>(null);
  const [removeFor, setRemoveFor] = useState<VulnItem | null>(null);
  const [scanning, setScanning] = useState<string | null>(null);

  /** Changes one filter and returns to the first page. Empty values leave the URL. */
  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("page");
    setParams(next, { replace: true });
  };

  const setPage = (p: number) => {
    const next = new URLSearchParams(params);
    if (p > 0) next.set("page", String(p));
    else next.delete("page");
    setParams(next, { replace: true });
  };

  // A boolean filter is sent only when ticked: `kev=false` would mean
  // "not exploited", not "any".
  const query = useMemo(() => {
    const q = new URLSearchParams();
    if (severity) q.set("severity", severity);
    if (kevOnly) q.set("kev", "true");
    if (kind) q.set("kind", kind);
    if (serverId) q.set("server_id", serverId);
    if (targetId) q.set("target_id", targetId);
    if (fixableOnly) q.set("fixable", "true");
    if (showAccepted) q.set("include_accepted", "true");
    if (showResolved) q.set("include_resolved", "true");
    if (groupByCve) q.set("group_by", "vuln");
    q.set("limit", String(PAGE_SIZE));
    q.set("offset", String(page * PAGE_SIZE));
    return q.toString();
  }, [severity, kevOnly, kind, serverId, targetId, fixableOnly, showAccepted, showResolved, groupByCve, page]);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setListError("");
    api
      .get<VulnList>(`/vulnerabilities?${query}`)
      .then((res) => {
        if (cancelled) return;
        setList({ items: Array.isArray(res.items) ? res.items : [], total: Number(res.total) || 0 });
      })
      .catch((e) => {
        if (cancelled) return;
        setList(null);
        setListError(e instanceof Error ? e.message : "Failed to load vulnerabilities");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [query, refreshKey]);

  const reload = useCallback(() => setRefreshKey((k) => k + 1), []);

  // Server names: the server list (admin), else whatever the findings carry.
  const serverNames = useMemo(() => {
    const m = new Map<string, string>();
    for (const it of list?.items ?? []) m.set(it.target.server_id, it.target.server_name);
    for (const s of servers) m.set(s.id, s.name);
    return m;
  }, [servers, list]);

  const serverOptions = useMemo(() => {
    const ids = new Set<string>();
    for (const s of summary?.servers ?? []) ids.add(s.server_id);
    for (const t of summary?.targets ?? []) ids.add(t.server_id);
    if (serverId) ids.add(serverId);
    return [...ids]
      .map((id) => ({ id, name: serverNames.get(id) ?? id.slice(0, 8) }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }, [summary, serverId, serverNames]);

  const targetOptions = useMemo(() => {
    const ts = (summary?.targets ?? []).filter((t) => (!serverId || t.server_id === serverId) && (!kind || t.kind === kind));
    return ts
      .map((t) => ({ id: t.id, label: `${capitalize(t.kind)}: ${targetLabel({ ...t, server_name: serverNames.get(t.server_id) })}` }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }, [summary, serverId, kind, serverNames]);

  const selectedTarget: VulnSummaryTarget | undefined = summary?.targets.find((t) => t.id === targetId);

  const scanTarget = async (id: string) => {
    setScanning(id);
    setMessage(null);
    try {
      await api.post(`/vulnerabilities/targets/${id}/scan`, {});
      setMessage({ text: "Scan queued", type: "success" });
    } catch (e) {
      setMessage({ text: `Scan failed: ${e instanceof Error ? e.message : "unknown error"}`, type: "error" });
    } finally {
      setScanning(null);
    }
  };

  const removeException = async () => {
    const item = removeFor;
    setRemoveFor(null);
    if (!item) return;
    setMessage(null);
    try {
      await api.delete(`/vulnerabilities/${item.id}/accept`);
      setMessage({ text: `Exception removed for ${item.vuln_id}`, type: "success" });
      reload();
    } catch (e) {
      setMessage({ text: `Could not remove the exception: ${e instanceof Error ? e.message : "unknown error"}`, type: "error" });
    }
  };

  const totals = summary?.totals;
  const cards: { label: string; value: number | undefined; tone: string; filter?: () => void; active?: boolean }[] = [
    { label: "Actively exploited", value: totals?.kev, tone: "text-danger-400", filter: () => setFilter("kev", kevOnly ? "" : "true"), active: kevOnly },
    { label: "Critical", value: totals?.critical, tone: "text-danger-400", filter: () => setFilter("severity", severity === "critical" ? "" : "critical"), active: severity === "critical" },
    { label: "High", value: totals?.high, tone: "text-warn-400", filter: () => setFilter("severity", severity === "high" ? "" : "high"), active: severity === "high" },
    { label: "Fixable", value: totals?.fixable, tone: "text-rust-400", filter: () => setFilter("fixable", fixableOnly ? "" : "true"), active: fixableOnly },
  ];

  const total = list?.total ?? 0;
  const pageCount = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const items = list?.items ?? [];

  return (
    <div>
      <div className="page-header">
        <div>
          <h1 className="page-header-title">Vulnerabilities</h1>
          <p className="page-header-subtitle">Known CVEs in the sites, Docker images and systems of your servers</p>
        </div>
        {targetId && (
          <button
            type="button"
            onClick={() => scanTarget(targetId)}
            disabled={scanning === targetId}
            aria-label={`Scan ${selectedTarget ? targetLabel({ ...selectedTarget, server_name: serverNames.get(selectedTarget.server_id) }) : "the selected target"} now`}
            className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
          >
            {scanning === targetId ? "Queuing..." : "Scan now"}
          </button>
        )}
      </div>

      <div className="p-6 lg:p-8 space-y-5">
        {message && (
          <div
            role={message.type === "error" ? "alert" : "status"}
            className={`px-4 py-3 rounded-lg text-sm border flex items-start justify-between gap-3 ${
              message.type === "success"
                ? "bg-rust-500/10 text-rust-400 border-rust-500/20"
                : "bg-danger-500/10 text-danger-400 border-danger-500/20"
            }`}
          >
            <span>{message.text}</span>
            <button type="button" onClick={() => setMessage(null)} aria-label="Dismiss message" className="text-xs opacity-70 hover:opacity-100">
              Dismiss
            </button>
          </div>
        )}

        {/* Totals (unresolved, accepted exceptions left out) */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
          {cards.map((c) => (
            <button
              key={c.label}
              type="button"
              onClick={c.filter}
              aria-pressed={c.active}
              aria-label={`${c.label}: ${c.value ?? "unknown"}. Filter the list`}
              className={`text-left bg-dark-800 rounded-lg border p-4 transition-colors hover:bg-dark-700/50 ${
                c.active ? "border-rust-500" : "border-dark-500"
              }`}
            >
              <div className="text-xs font-mono text-dark-300 uppercase tracking-widest">{c.label}</div>
              <div className={`text-2xl font-bold mt-1 ${c.tone}`}>{c.value ?? "-"}</div>
            </button>
          ))}
        </div>

        {/* Scanner state per server (admin) */}
        {isAdmin && summary && summary.servers.length > 0 && (
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
            <div className="px-5 py-3 border-b border-dark-600">
              <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Scanner state</h2>
            </div>
            <ul className="divide-y divide-dark-600">
              {summary.servers.map((s) => (
                <li key={s.server_id} className="px-5 py-3 text-sm flex flex-wrap items-center gap-x-6 gap-y-1">
                  <span className="font-medium text-dark-50">{serverNames.get(s.server_id) ?? s.server_id.slice(0, 8)}</span>
                  <span className="text-dark-200">
                    Database built: {s.db_built ? <span title={formatDate(s.db_built)}>{timeAgo(s.db_built)}</span> : "never"}
                  </span>
                  <span className="text-dark-200">
                    Last match: {s.last_match_at ? <span title={formatDate(s.last_match_at)}>{timeAgo(s.last_match_at)}</span> : "never"}
                  </span>
                  {s.last_error && <span className="text-danger-400 break-all">Error: {s.last_error}</span>}
                </li>
              ))}
            </ul>
          </div>
        )}

        {/* Filters */}
        <div className="bg-dark-800 rounded-lg border border-dark-500 p-4">
          <div className="flex flex-wrap items-end gap-3">
            <div className="flex flex-col gap-1">
              <label htmlFor="vf-severity" className="text-[10px] font-mono text-dark-300 uppercase tracking-widest">Severity</label>
              <select id="vf-severity" value={severity} onChange={(e) => setFilter("severity", e.target.value)} className={inputCls}>
                <option value="">Any</option>
                {SEVERITY_OPTIONS.map((s) => (
                  <option key={s} value={s}>{capitalize(s)}</option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="vf-kind" className="text-[10px] font-mono text-dark-300 uppercase tracking-widest">Target type</label>
              <select id="vf-kind" value={kind} onChange={(e) => setFilter("kind", e.target.value)} className={inputCls}>
                <option value="">Any</option>
                {KIND_OPTIONS.map((k) => (
                  <option key={k.value} value={k.value}>{k.label}</option>
                ))}
              </select>
            </div>
            {(serverOptions.length > 1 || serverId) && (
              <div className="flex flex-col gap-1">
                <label htmlFor="vf-server" className="text-[10px] font-mono text-dark-300 uppercase tracking-widest">Server</label>
                <select id="vf-server" value={serverId} onChange={(e) => setFilter("server_id", e.target.value)} className={inputCls}>
                  <option value="">Any</option>
                  {serverOptions.map((s) => (
                    <option key={s.id} value={s.id}>{s.name}</option>
                  ))}
                </select>
              </div>
            )}
            <div className="flex flex-col gap-1 min-w-0">
              <label htmlFor="vf-target" className="text-[10px] font-mono text-dark-300 uppercase tracking-widest">Target</label>
              <select id="vf-target" value={targetId} onChange={(e) => setFilter("target_id", e.target.value)} className={`${inputCls} max-w-xs`}>
                <option value="">Any</option>
                {targetId && !targetOptions.some((t) => t.id === targetId) && <option value={targetId}>Selected target</option>}
                {targetOptions.map((t) => (
                  <option key={t.id} value={t.id}>{t.label}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 mt-3 text-sm text-dark-100">
            {[
              { key: "kev", label: "Actively exploited", checked: kevOnly },
              { key: "fixable", label: "Fixable only", checked: fixableOnly },
              { key: "include_accepted", label: "Show accepted", checked: showAccepted },
              { key: "include_resolved", label: "Show resolved", checked: showResolved },
            ].map((f) => (
              <label key={f.key} className="inline-flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={f.checked} onChange={(e) => setFilter(f.key, e.target.checked ? "true" : "")} />
                {f.label}
              </label>
            ))}
            <label className="inline-flex items-center gap-2 cursor-pointer">
              <input type="checkbox" checked={groupByCve} onChange={(e) => setFilter("group", e.target.checked ? "" : "none")} />
              Group by CVE
            </label>
          </div>
        </div>

        {listError && (
          <div role="alert" className="px-4 py-3 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20 flex items-center justify-between gap-3">
            <span>Could not load vulnerabilities: {listError}</span>
            <button type="button" onClick={reload} className={btnSecondary}>Retry</button>
          </div>
        )}

        {/* Findings */}
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <caption className="sr-only">Vulnerabilities found by the scanner</caption>
              <thead>
                <tr className="text-left text-[10px] font-mono text-dark-300 uppercase tracking-widest border-b border-dark-600">
                  <th scope="col" className="px-4 py-3">CVE</th>
                  <th scope="col" className="px-4 py-3">Severity</th>
                  <th scope="col" className="px-4 py-3">Exploited</th>
                  <th scope="col" className="px-4 py-3">EPSS</th>
                  <th scope="col" className="px-4 py-3">Target</th>
                  <th scope="col" className="px-4 py-3">Component</th>
                  <th scope="col" className="px-4 py-3">Installed</th>
                  <th scope="col" className="px-4 py-3">Fixed in</th>
                  <th scope="col" className="px-4 py-3">First seen</th>
                  <th scope="col" className="px-4 py-3"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-dark-600">
                {loading && items.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-4 py-8 text-center text-dark-300">Loading...</td>
                  </tr>
                )}
                {!loading && !listError && items.length === 0 && (
                  <tr>
                    <td colSpan={10} className="px-4 py-8 text-center text-dark-300">
                      {summaryState.summary && summaryState.summary.targets.length === 0
                        ? "Nothing scanned yet. The scanner checks every server once a day."
                        : "No vulnerabilities match these filters."}
                    </td>
                  </tr>
                )}
                {items.map((item) => {
                  const rowKey = `${item.target_id}:${item.vuln_id}:${item.id}`;
                  const open = expanded === rowKey;
                  const pkgs = packagesOf(item);
                  const link = advisoryUrl(item);
                  const tLabel = targetLabel(item.target);
                  const detailId = `vuln-detail-${item.id}`;
                  return (
                    <Fragment key={rowKey}>
                      <tr className={`${open ? "bg-dark-700/50" : "hover:bg-dark-700/30"} ${item.resolved_at ? "opacity-60" : ""}`}>
                        <td className="px-4 py-3 font-mono whitespace-nowrap">
                          <button
                            type="button"
                            onClick={() => setExpanded(open ? null : rowKey)}
                            aria-expanded={open}
                            aria-controls={detailId}
                            aria-label={`${open ? "Hide" : "Show"} details of ${item.vuln_id} on ${tLabel}`}
                            className="mr-2 text-dark-300 hover:text-dark-100"
                          >
                            <svg className={`w-3 h-3 inline transition-transform ${open ? "rotate-90" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} aria-hidden="true">
                              <path strokeLinecap="round" strokeLinejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
                            </svg>
                          </button>
                          {link ? (
                            <a href={link} target="_blank" rel="noopener noreferrer" className="text-rust-400 hover:text-rust-300" aria-label={`${item.vuln_id} advisory (opens in a new tab)`}>
                              {item.vuln_id}
                            </a>
                          ) : (
                            <span className="text-dark-50">{item.vuln_id}</span>
                          )}
                          {item.accepted && (
                            <span className="ml-2 inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-dark-700 text-dark-200" title={`Accepted until ${formatDate(item.accepted.expires_at)}`}>
                              Accepted
                            </span>
                          )}
                          {item.resolved_at && (
                            <span className="ml-2 inline-flex px-1.5 py-0.5 rounded text-[10px] font-medium bg-rust-500/15 text-rust-400" title={`Resolved ${formatDate(item.resolved_at)}`}>
                              Resolved
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <span className={`inline-flex px-2 py-0.5 rounded-full text-[10px] font-medium ${SEVERITY_CLASS[item.severity] ?? "bg-dark-700 text-dark-300"}`}>
                            {capitalize(item.severity)}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {item.kev ? (
                            <span
                              className="inline-flex px-2 py-0.5 rounded-full text-[10px] font-medium bg-danger-500/15 text-danger-400"
                              title={item.kev_ransomware ? "In the CISA KEV catalog, used by ransomware" : "In the CISA KEV catalog"}
                            >
                              {item.kev_ransomware ? "Ransomware" : "Exploited"}
                            </span>
                          ) : (
                            <span className="text-dark-400" aria-label="Not known to be exploited">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 font-mono text-dark-200" title={item.epss_percentile != null ? `Percentile ${(item.epss_percentile * 100).toFixed(0)}` : undefined}>
                          {item.epss != null ? `${(item.epss * 100).toFixed(1)}%` : "-"}
                        </td>
                        <td className="px-4 py-3 text-dark-100">
                          <span className="block max-w-[14rem] truncate" title={`${tLabel} on ${item.target.server_name}`}>{tLabel}</span>
                        </td>
                        <td className="px-4 py-3 font-mono text-dark-100">
                          <span className="block max-w-[14rem] truncate" title={pkgs.map((p) => p.package).join(", ")}>
                            {pkgs[0].package}
                            {pkgs.length > 1 && <span className="text-dark-300"> +{pkgs.length - 1}</span>}
                          </span>
                        </td>
                        <td className="px-4 py-3 font-mono text-dark-200 whitespace-nowrap">{pkgs[0].version}</td>
                        <td className="px-4 py-3 font-mono whitespace-nowrap">
                          {item.fixed_version ? <span className="text-rust-400">{item.fixed_version}</span> : <span className="text-dark-400">-</span>}
                        </td>
                        <td className="px-4 py-3 text-dark-200 whitespace-nowrap" title={formatDate(item.first_seen)}>{timeAgo(item.first_seen)}</td>
                        <td className="px-4 py-3 whitespace-nowrap text-right">
                          {isAdmin && !item.resolved_at && (
                            item.accepted ? (
                              <button type="button" onClick={() => setRemoveFor(item)} className={btnSecondary} aria-label={`Remove the exception for ${item.vuln_id} on ${tLabel}`}>
                                Remove exception
                              </button>
                            ) : (
                              <button type="button" onClick={() => setAcceptFor(item)} className={btnSecondary} aria-label={`Accept the risk of ${item.vuln_id} on ${tLabel}`}>
                                Accept
                              </button>
                            )
                          )}
                        </td>
                      </tr>
                      {open && (
                        <tr id={detailId} className="bg-dark-900/40">
                          <td colSpan={10} className="px-6 py-4 space-y-3 text-sm">
                            {item.title && <p className="text-dark-100">{item.title}</p>}
                            <dl className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-1 text-xs">
                              <div><dt className="inline text-dark-300">Target: </dt><dd className="inline text-dark-100">{capitalize(item.target.kind)} {tLabel} on {item.target.server_name}</dd></div>
                              {item.cvss != null && <div><dt className="inline text-dark-300">CVSS: </dt><dd className="inline text-dark-100 font-mono">{item.cvss.toFixed(1)}</dd></div>}
                              {item.risk != null && <div><dt className="inline text-dark-300">Risk score: </dt><dd className="inline text-dark-100 font-mono">{item.risk.toFixed(1)}</dd></div>}
                              <div><dt className="inline text-dark-300">Fix: </dt><dd className="inline text-dark-100">{item.fix_state}</dd></div>
                              <div><dt className="inline text-dark-300">Last seen: </dt><dd className="inline text-dark-100">{formatDate(item.last_seen)}</dd></div>
                              {item.aliases?.length > 0 && <div><dt className="inline text-dark-300">Aliases: </dt><dd className="inline text-dark-100 font-mono">{item.aliases.join(", ")}</dd></div>}
                            </dl>
                            <div className="overflow-x-auto">
                              <table className="w-full text-xs">
                                <caption className="sr-only">Affected packages of {item.vuln_id}</caption>
                                <thead>
                                  <tr className="text-left text-dark-300 font-mono uppercase tracking-widest">
                                    <th scope="col" className="pr-4 py-1">Package</th>
                                    <th scope="col" className="pr-4 py-1">Installed</th>
                                    <th scope="col" className="pr-4 py-1">Fixed in</th>
                                    <th scope="col" className="pr-4 py-1">Path</th>
                                  </tr>
                                </thead>
                                <tbody>
                                  {pkgs.map((p, i) => (
                                    <tr key={`${p.package}:${p.version}:${p.location ?? ""}:${i}`} className="font-mono text-dark-100">
                                      <td className="pr-4 py-1">{p.package}</td>
                                      <td className="pr-4 py-1">{p.version}</td>
                                      <td className="pr-4 py-1">{p.fixed_version ?? "-"}</td>
                                      <td className="pr-4 py-1 break-all">{p.location ?? "-"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                            {item.accepted && (
                              <div className="border border-dark-600 rounded p-3 text-xs text-dark-200">
                                <div className="font-medium text-dark-100">Exception</div>
                                <p className="mt-1 whitespace-pre-line">{item.accepted.reason}</p>
                                <p className="mt-1 text-dark-300">
                                  Expires {formatDate(item.accepted.expires_at)}
                                  {item.accepted.created_by_email ? `, accepted by ${item.accepted.created_by_email}` : ""}
                                </p>
                              </div>
                            )}
                            <div>
                              <button
                                type="button"
                                onClick={() => scanTarget(item.target_id)}
                                disabled={scanning === item.target_id}
                                className={btnSecondary}
                                aria-label={`Scan ${tLabel} now`}
                              >
                                {scanning === item.target_id ? "Queuing..." : "Scan now"}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="px-4 py-3 border-t border-dark-600 flex flex-wrap items-center justify-between gap-3 text-xs text-dark-300">
            <span>
              {total} {groupByCve ? (total === 1 ? "CVE" : "CVEs") : total === 1 ? "finding" : "findings"}
              {total > PAGE_SIZE && ` (page ${page + 1} of ${pageCount})`}
            </span>
            {total > PAGE_SIZE && (
              <div className="flex gap-2">
                <button type="button" onClick={() => setPage(page - 1)} disabled={page === 0 || loading} className={btnSecondary} aria-label="Previous page">
                  Previous
                </button>
                <button type="button" onClick={() => setPage(page + 1)} disabled={page + 1 >= pageCount || loading} className={btnSecondary} aria-label="Next page">
                  Next
                </button>
              </div>
            )}
          </div>
        </div>

        <p className="text-[11px] text-dark-300">
          Vulnerability data: Anchore grype database (NVD, GitHub Security Advisories, distribution advisories), CISA KEV, FIRST EPSS.
        </p>
      </div>

      {acceptFor && (
        <AcceptDialog
          item={acceptFor}
          onCancel={() => setAcceptFor(null)}
          onDone={(text) => {
            setAcceptFor(null);
            setMessage({ text, type: "success" });
            reload();
          }}
        />
      )}

      {removeFor && (
        <ConfirmDialog
          label={`Remove the exception for ${removeFor.vuln_id} on ${targetLabel(removeFor.target)}? It counts again in the totals and alerts.`}
          confirmLabel="Remove exception"
          tone="warn"
          onConfirm={removeException}
          onCancel={() => setRemoveFor(null)}
        />
      )}
    </div>
  );
}

/** Accept the risk of a CVE on one target (admin): a reason and an expiry, 90 days at most. */
function AcceptDialog({ item, onCancel, onDone }: { item: VulnItem; onCancel: () => void; onDone: (message: string) => void }) {
  const [reason, setReason] = useState("");
  const [day, setDay] = useState(() => dateInputValue(addDays(DEFAULT_ACCEPT_DAYS)));
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const reasonRef = useRef<HTMLTextAreaElement>(null);
  const minDay = dateInputValue(addDays(1));
  const maxDay = dateInputValue(addDays(MAX_ACCEPT_DAYS));

  useEffect(() => {
    reasonRef.current?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onCancel();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onCancel]);

  const trimmed = reason.trim();
  const dayInRange = day >= minDay && day <= maxDay;
  const valid = trimmed.length > 0 && trimmed.length <= 500 && dayInRange;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const expires = dayInRange ? acceptExpiry(day) : null;
    if (!trimmed || !expires) {
      setError(!trimmed ? "A reason is required." : `Pick a date between tomorrow and ${MAX_ACCEPT_DAYS} days from now.`);
      return;
    }
    setSaving(true);
    setError("");
    try {
      await api.post(`/vulnerabilities/${item.id}/accept`, { reason: trimmed, expires_at: expires });
      onDone(`${item.vuln_id} accepted until ${formatDate(expires)}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the exception");
      setSaving(false);
    }
  };

  return createPortal(
    <div
      className="fixed inset-0 bg-black/40 flex items-center justify-center z-50 p-4 dp-modal-overlay"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <form
        role="dialog"
        aria-modal="true"
        aria-labelledby="vuln-accept-title"
        onSubmit={submit}
        className="bg-dark-800 rounded-lg shadow-xl p-6 w-full max-w-md dp-modal space-y-4"
      >
        <h2 id="vuln-accept-title" className="text-sm font-medium text-dark-50">
          Accept {item.vuln_id} on {targetLabel(item.target)}
        </h2>
        <p className="text-xs text-dark-300">
          An accepted CVE leaves the totals and the alerts until the exception expires. It stays listed under Show accepted.
        </p>
        <div className="space-y-1">
          <label htmlFor="vuln-accept-reason" className="block text-xs font-mono text-dark-300 uppercase tracking-widest">Reason</label>
          <textarea
            id="vuln-accept-reason"
            ref={reasonRef}
            required
            maxLength={500}
            rows={3}
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            className="w-full px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-sm text-dark-50"
          />
          <p className="text-[10px] text-dark-300 text-right">{trimmed.length}/500</p>
        </div>
        <div className="space-y-1">
          <label htmlFor="vuln-accept-expiry" className="block text-xs font-mono text-dark-300 uppercase tracking-widest">Expires on</label>
          <input
            id="vuln-accept-expiry"
            type="date"
            required
            min={minDay}
            max={maxDay}
            value={day}
            onChange={(e) => setDay(e.target.value)}
            className="w-full px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-sm text-dark-50"
          />
          <p className="text-[10px] text-dark-300">{MAX_ACCEPT_DAYS} days at most.</p>
        </div>
        {error && <p role="alert" className="text-xs text-danger-400">{error}</p>}
        <div className="flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 bg-dark-600 text-dark-200 text-xs font-bold uppercase tracking-wider rounded hover:bg-dark-500 transition-colors"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={!valid || saving}
            className="px-4 py-2 bg-warn-500 text-white text-xs font-bold uppercase tracking-wider rounded hover:bg-warn-600 disabled:opacity-50 transition-colors"
          >
            {saving ? "Saving..." : "Accept"}
          </button>
        </div>
      </form>
    </div>,
    document.body,
  );
}
