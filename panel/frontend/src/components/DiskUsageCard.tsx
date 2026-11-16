import { useState, useEffect } from "react";
import { api, ApiError } from "../api";
import { formatSize, timeAgo, formatDate } from "../utils/format";

// ── Shapes (07-ftp-quotas-contrats.md B-3) ───────────────────────────────────

/** `disk_usage` of the site JSON (detail and list). */
export interface DiskUsage {
  bytes: number | null;
  files: number | null;
  measured_at: string;
  error: string | null;
}

const MB = 1024 * 1024;
const UNITS = ["B", "KB", "MB", "GB", "TB"];

/** Bytes of a quota given in MB. */
export const quotaBytes = (quotaMb: number) => quotaMb * MB;

/** One decimal, trailing ".0" dropped ("2" rather than "2.0"). */
const trim1 = (n: number) => {
  const s = n.toFixed(1);
  return s.endsWith(".0") ? s.slice(0, -2) : s;
};

/**
 * "1.2 GB" without a quota, "1.2 / 2 GB" with one (both values in the
 * quota's unit, base 1024, one decimal).
 */
export function formatUsage(bytes: number, quotaMb: number | null | undefined): string {
  if (!quotaMb) return formatSize(bytes);
  const q = quotaBytes(quotaMb);
  const i = Math.max(0, Math.min(UNITS.length - 1, Math.floor(Math.log(q) / Math.log(1024))));
  const div = Math.pow(1024, i);
  return `${(bytes / div).toFixed(i === 0 ? 0 : 1)} / ${trim1(q / div)} ${UNITS[i]}`;
}

/** Used share of the quota (1 = 100 %), or null without a quota or a measure. */
export function quotaRatio(bytes: number | null | undefined, quotaMb: number | null | undefined): number | null {
  if (bytes == null || !quotaMb) return null;
  return bytes / quotaBytes(quotaMb);
}

/** Bar and text colour: green, orange from 90 %, red from 100 % (B-4 thresholds). */
export function quotaTone(ratio: number | null): "ok" | "warn" | "over" {
  if (ratio == null || ratio < 0.9) return "ok";
  return ratio >= 1 ? "over" : "warn";
}

/** Quota field text for a stored value in MB ("" = unlimited). */
const mbToGbField = (mb: number | null | undefined) => (mb ? trim1(mb / 1024) : "");

/** Field text -> MB to send. `undefined` = invalid. */
function gbFieldToMb(v: string): number | null | undefined {
  const t = v.trim();
  if (!t) return null;
  if (!/^\d*\.?\d+$|^\d+\.$/.test(t)) return undefined;
  const mb = Math.round(parseFloat(t) * 1024);
  return Number.isFinite(mb) && mb > 0 ? mb : undefined;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

interface Props {
  siteId: string;
  usage: DiskUsage | null | undefined;
  quotaMb: number | null | undefined;
  /** Admin, or the reseller of the site's client: may set the quota. */
  canEditQuota: boolean;
  /** Called with the new values so the page's copy of the site stays current. */
  onChange: (patch: { disk_usage?: DiskUsage | null; disk_quota_mb?: number | null }) => void;
}

/**
 * Site detail -> Disk usage: measured size of /var/www/<domain> against the
 * site's quota, "Refresh" for an immediate measure, and the quota field for
 * whoever may set it. The quota only raises alerts, it never blocks writes.
 */
export default function DiskUsageCard({ siteId, usage, quotaMb, canEditQuota, onChange }: Props) {
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [quotaField, setQuotaField] = useState(mbToGbField(quotaMb));
  const [msg, setMsg] = useState<{ text: string; type: "success" | "error" } | null>(null);

  // Follow the stored value (site reload, save) unless the field is being edited.
  useEffect(() => {
    setQuotaField(mbToGbField(quotaMb));
  }, [quotaMb]);

  const bytes = usage?.bytes ?? null;
  const ratio = quotaRatio(bytes, quotaMb);
  const tone = quotaTone(ratio);
  const barColor = tone === "over" ? "bg-danger-500" : tone === "warn" ? "bg-warn-500" : "bg-rust-500";
  const textColor = tone === "over" ? "text-danger-400" : tone === "warn" ? "text-warn-400" : "text-dark-50";

  const parsedQuota = gbFieldToMb(quotaField);
  const quotaInvalid = parsedQuota === undefined;
  const quotaChanged = quotaField.trim() !== mbToGbField(quotaMb);

  const refresh = async () => {
    setRefreshing(true);
    setMsg(null);
    try {
      // B-3 says the route "returns disk_usage": accept it bare or wrapped.
      const r = await api.post<DiskUsage | { disk_usage: DiskUsage | null }>(`/sites/${siteId}/disk-usage/refresh`);
      const fresh = r && "disk_usage" in r ? r.disk_usage : (r as DiskUsage);
      onChange({ disk_usage: fresh ?? null });
    } catch (e) {
      if (e instanceof ApiError && e.status === 429) {
        setMsg({ text: "A measurement is already running for this site", type: "error" });
      } else {
        setMsg({ text: errText(e, "Measurement failed"), type: "error" });
      }
    } finally {
      setRefreshing(false);
    }
  };

  const saveQuota = async () => {
    if (quotaInvalid) return;
    setSaving(true);
    setMsg(null);
    try {
      await api.put(`/sites/${siteId}/disk-quota`, { quota_mb: parsedQuota });
      onChange({ disk_quota_mb: parsedQuota });
      setQuotaField(mbToGbField(parsedQuota));
      setMsg({ text: parsedQuota ? "Quota saved" : "Quota removed", type: "success" });
    } catch (e) {
      setMsg({ text: errText(e, "Could not save the quota"), type: "error" });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
      <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
        <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Disk usage</h2>
        <button
          onClick={refresh}
          disabled={refreshing}
          className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded-lg text-xs font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
        >
          {refreshing ? "Measuring..." : "Refresh"}
        </button>
      </div>
      <div className="p-5 space-y-4">
        {!usage ? (
          <p className="text-sm text-dark-300">Not measured yet. Sites are measured every 6 hours, or click Refresh.</p>
        ) : (
          <div className="space-y-2">
            <div className="flex items-baseline justify-between gap-3 flex-wrap">
              <span className={`text-lg font-mono ${textColor}`}>
                {bytes == null ? "-" : formatUsage(bytes, quotaMb)}
                {!quotaMb && <span className="text-xs text-dark-300 ml-2 font-sans">Unlimited</span>}
              </span>
              <span className="text-xs text-dark-300">
                {ratio != null && <span className={`mr-3 font-mono ${textColor}`}>{Math.round(ratio * 100)}%</span>}
                {usage.files != null && <span className="mr-3">{usage.files.toLocaleString()} files</span>}
                <span title={formatDate(usage.measured_at)}>Measured {timeAgo(usage.measured_at)}</span>
              </span>
            </div>
            {ratio != null && (
              <div
                className="h-2 bg-dark-700 rounded-full overflow-hidden"
                role="progressbar"
                aria-valuemin={0}
                aria-valuemax={100}
                aria-valuenow={Math.min(100, Math.round(ratio * 100))}
              >
                <div className={`h-full ${barColor} transition-all`} style={{ width: `${Math.min(100, ratio * 100)}%` }} />
              </div>
            )}
            {tone === "over" && (
              <p className="text-xs text-danger-400">Over quota. The site keeps working; this limit only raises an alert.</p>
            )}
            {usage.error && (
              <p className="text-xs px-3 py-2 rounded-lg bg-warn-500/10 text-warn-400 border border-warn-500/30">
                Last measurement failed: {usage.error}
              </p>
            )}
          </div>
        )}

        {canEditQuota ? (
          <div className="flex items-end gap-3 flex-wrap">
            <div className="max-w-[10rem]">
              <label htmlFor="disk-quota-gb" className="block text-xs font-medium text-dark-200 mb-1">
                Quota (GB)
              </label>
              <input
                id="disk-quota-gb"
                type="text"
                inputMode="decimal"
                value={quotaField}
                onChange={(e) => setQuotaField(e.target.value)}
                placeholder="Unlimited"
                autoComplete="off"
                className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
              />
            </div>
            <button
              onClick={saveQuota}
              disabled={saving || quotaInvalid || !quotaChanged}
              className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
            >
              {saving ? "Saving..." : "Save"}
            </button>
            <p className={`text-xs w-full ${quotaInvalid ? "text-danger-400" : "text-dark-400"}`}>
              {quotaInvalid
                ? "Enter a size in GB greater than 0 (decimals allowed), or leave empty for unlimited."
                : "Leave empty for unlimited. An alert is raised at 90% and when the quota is exceeded; nothing is blocked."}
            </p>
          </div>
        ) : (
          <p className="text-xs text-dark-300">
            Quota: <span className="text-dark-100 font-mono">{quotaMb ? formatSize(quotaBytes(quotaMb)) : "Unlimited"}</span>
          </p>
        )}

        {msg && (
          <p className={`text-xs ${msg.type === "success" ? "text-rust-400" : "text-danger-400"}`}>{msg.text}</p>
        )}
      </div>
    </div>
  );
}
