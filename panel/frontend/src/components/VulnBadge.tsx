import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

/**
 * CVE scanner badge (conception 13, batch 3).
 *
 * A page calls `useVulnSummary()` ONCE and hands each row the target it found
 * in that one answer, so a list of fifty apps costs one request, not fifty.
 * The badge never breaks the page it sits on: a 403, 404 or 500 from the
 * summary hides every badge instead of showing an error.
 */

export interface VulnSummaryTarget {
  id: string;
  kind: string;
  ref: string;
  server_id: string;
  site_id: string | null;
  app_name: string | null;
  git_deploy_id: string | null;
  kev: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  sbom_at: string | null;
  matched_at: string | null;
  last_error: string | null;
}

export interface VulnSummaryServer {
  server_id: string;
  db_built: string | null;
  last_match_at: string | null;
  last_error: string | null;
}

export interface VulnSummary {
  totals: { kev: number; critical: number; high: number; medium: number; low: number; fixable: number };
  targets: VulnSummaryTarget[];
  servers: VulnSummaryServer[];
}

export interface VulnSummaryState {
  /** The answer, or null while loading or after a failure. */
  summary: VulnSummary | null;
  /** True once the request settled (success or failure). */
  loaded: boolean;
  /** True when the request failed: badges render nothing. */
  failed: boolean;
}

/** One `GET /api/vulnerabilities/summary` per mount (and per `refreshKey` change). */
export function useVulnSummary(enabled = true, refreshKey: unknown = 0): VulnSummaryState {
  const [state, setState] = useState<VulnSummaryState>({ summary: null, loaded: false, failed: false });
  useEffect(() => {
    if (!enabled) {
      setState({ summary: null, loaded: true, failed: true });
      return;
    }
    let cancelled = false;
    api
      .get<VulnSummary>("/vulnerabilities/summary")
      .then((s) => {
        if (cancelled) return;
        if (!s || !Array.isArray(s.targets)) {
          setState({ summary: null, loaded: true, failed: true });
          return;
        }
        setState({ summary: s, loaded: true, failed: false });
      })
      .catch(() => {
        // Scanner absent, not allowed or broken: no badge, never an error here.
        if (!cancelled) setState({ summary: null, loaded: true, failed: true });
      });
    return () => {
      cancelled = true;
    };
  }, [enabled, refreshKey]);
  return state;
}

/** Same colour code as `scanSeverityClass` in Apps.tsx. */
export function vulnBadgeClass(t: VulnSummaryTarget | undefined): string {
  if (!t || !t.matched_at) return "bg-dark-700 text-dark-300";
  if (t.kev > 0 || t.critical > 0) return "bg-danger-500/15 text-danger-400";
  if (t.high > 0) return "bg-warn-500/15 text-warn-400";
  if (t.medium > 0) return "bg-warn-500/10 text-warn-500";
  if (t.low > 0) return "bg-accent-500/10 text-accent-400";
  return "bg-rust-500/15 text-rust-400";
}

export function vulnBadgeLabel(t: VulnSummaryTarget | undefined): string {
  if (!t || !t.matched_at) return "Not scanned";
  if (t.kev > 0) return `${t.kev} exploited`;
  if (t.critical > 0 || t.high > 0) return `${t.critical}C / ${t.high}H`;
  if (t.medium > 0) return `${t.medium}M`;
  if (t.low > 0) return `${t.low}L`;
  return "Clean";
}

/**
 * The pill. `subject` names what is scanned, for the accessible label
 * ("site example.com", "image nginx:1.21").
 */
export default function VulnBadge({
  state,
  target,
  subject,
}: {
  state: VulnSummaryState;
  target: VulnSummaryTarget | undefined;
  subject: string;
}) {
  if (!state.loaded || state.failed) return null;
  const label = vulnBadgeLabel(target);
  const cls = `inline-flex items-center px-1.5 py-0.5 rounded-full text-[10px] font-medium ${vulnBadgeClass(target)}`;
  if (!target) {
    return (
      <span className={cls} title="Not yet scanned for vulnerabilities" aria-label={`Vulnerabilities of ${subject}: not scanned`}>
        {label}
      </span>
    );
  }
  const when = target.matched_at ? `last checked ${new Date(target.matched_at).toLocaleString()}` : "not yet checked";
  return (
    <Link
      to={`/vulnerabilities?target_id=${encodeURIComponent(target.id)}`}
      onClick={(e) => e.stopPropagation()}
      className={`${cls} hover:opacity-80`}
      title={`Vulnerabilities: ${label}, ${when}`}
      aria-label={`Open vulnerabilities of ${subject}: ${label}`}
    >
      {label}
    </Link>
  );
}
