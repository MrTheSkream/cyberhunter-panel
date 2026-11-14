import { useEffect, useMemo, useState } from "react";
import { api, ApiError } from "../api";
import ConfirmDialog from "./ConfirmDialog";
import {
  type PhpField,
  type PhpPool,
  type PhpSettingsResponse,
  type PhpSettingsUpdate,
  POOL_MAX_CHILDREN,
  SHELL_FUNCTIONS,
  changedPool,
  changedValues,
  cleanExtra,
  extraEqual,
  fromInputText,
  toInputText,
  validateExtra,
  validateFieldValue,
} from "../utils/phpSettings";

const inputCls =
  "w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none";
const inputErrCls =
  "w-full px-3 py-2 border border-danger-500 rounded-lg text-sm focus:ring-2 focus:ring-danger-500 focus:border-danger-500 outline-none";
const btnPrimary =
  "px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors";
const btnSecondary =
  "px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 disabled:opacity-50 transition-colors";
const sectionTitle = "text-xs font-medium text-dark-300 uppercase font-mono tracking-widest";

/** On/Off pair. `value` null = neither shown as active (inherited from php.ini). */
function OnOff({
  value,
  onChange,
  disabled,
  labels = ["On", "Off"],
}: {
  value: boolean | null;
  onChange: (v: boolean) => void;
  disabled?: boolean;
  labels?: [string, string];
}) {
  const base = "px-3 py-1.5 text-xs font-medium transition-colors disabled:opacity-50";
  return (
    <div className="inline-flex rounded-lg border border-dark-500 overflow-hidden">
      <button
        type="button"
        disabled={disabled}
        aria-pressed={value === true}
        onClick={() => onChange(true)}
        className={`${base} ${value === true ? "bg-rust-500 text-white" : "text-dark-300 hover:text-dark-100"}`}
      >
        {labels[0]}
      </button>
      <button
        type="button"
        disabled={disabled}
        aria-pressed={value === false}
        onClick={() => onChange(false)}
        className={`${base} border-l border-dark-500 ${value === false ? "bg-dark-600 text-dark-50" : "text-dark-300 hover:text-dark-100"}`}
      >
        {labels[1]}
      </button>
    </div>
  );
}

const INHERITED = "inherited from global php.ini";

function defaultLabel(field: PhpField, v: string | undefined): string {
  if (v == null) return "—";
  if (field.kind === "choice") return field.choices?.find((c) => c.value === v)?.label ?? v;
  return v;
}

interface Props {
  siteId: string;
  /**
   * Changes whenever a site column the defaults derive from changes
   * (php_memory_mb, max_upload_mb, php_max_workers, php_version), so the card
   * re-reads its settings after a Resource Limits save or a version switch.
   */
  refreshKey: string;
  /** Called after a successful save, so the page can re-read the site. */
  onSaved?: () => void;
}

/**
 * The "PHP settings" card of a PHP site (contract B1/B2). The owner edits the
 * php.ini values; an admin (`can_admin`) also edits isolation, the FPM pool and
 * free directives. Only what changed is sent.
 */
export default function PhpSettingsCard({ siteId, refreshKey, onSaved }: Props) {
  const [data, setData] = useState<PhpSettingsResponse | null>(null);
  const [loadError, setLoadError] = useState("");
  const [loading, setLoading] = useState(true);
  // Only what the user touched; null = reset to the default.
  const [edits, setEdits] = useState<Record<string, string | null>>({});
  const [isolation, setIsolation] = useState(false);
  const [disableShell, setDisableShell] = useState(false);
  const [pool, setPool] = useState<PhpPool | null>(null);
  const [extra, setExtra] = useState<[string, string][]>([]);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);
  const [serverField, setServerField] = useState<string | null>(null);
  const [confirmPanelDefaults, setConfirmPanelDefaults] = useState(false);

  const adopt = (d: PhpSettingsResponse) => {
    setData(d);
    setEdits({});
    setIsolation(d.isolation);
    setDisableShell(d.disable_shell);
    setPool({ ...d.pool });
    setExtra(d.extra.map(([k, v]) => [k, v] as [string, string]));
    setServerField(null);
  };

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setLoadError("");
    api
      .get<PhpSettingsResponse>(`/sites/${siteId}/php-settings`)
      .then((d) => { if (!cancelled) adopt(d); })
      .catch((e) => { if (!cancelled) setLoadError(e instanceof Error ? e.message : "Could not load PHP settings"); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [siteId, refreshKey]);

  const valueOf = (key: string): string | null => {
    if (Object.prototype.hasOwnProperty.call(edits, key)) return edits[key];
    return data && Object.prototype.hasOwnProperty.call(data.values, key) ? data.values[key] : null;
  };

  const fieldErrors = useMemo(() => {
    const out: Record<string, string> = {};
    if (!data) return out;
    for (const f of data.fields) {
      const err = validateFieldValue(f, valueOf(f.key));
      if (err) out[f.key] = err;
    }
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data, edits]);

  const cleanedExtra = useMemo(() => cleanExtra(extra), [extra]);
  const extraErrors = useMemo(
    () => extra.map(([k, v]) => (k.trim() === "" && v.trim() === "" ? null : validateExtra(k.trim(), v.trim()))),
    [extra],
  );

  if (loading && !data) {
    return (
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
        <div className="px-5 py-4 border-b border-dark-600"><h2 className={sectionTitle}>PHP Settings</h2></div>
        <div className="p-5 text-sm text-dark-300">Loading...</div>
      </div>
    );
  }
  if (!data || !pool) {
    return (
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
        <div className="px-5 py-4 border-b border-dark-600"><h2 className={sectionTitle}>PHP Settings</h2></div>
        <div className="p-5 text-sm text-danger-400">{loadError || "Could not load PHP settings"}</div>
      </div>
    );
  }

  const valuesDiff = changedValues(data.values, edits);
  const poolDiff = data.can_admin ? changedPool(data.pool, pool) : {};
  const isolationChanged = data.can_admin && isolation !== data.isolation;
  const shellChanged = data.can_admin && disableShell !== data.disable_shell;
  const extraChanged = data.can_admin && !extraEqual(cleanedExtra, data.extra);
  const dirty =
    Object.keys(valuesDiff).length > 0 ||
    Object.keys(poolDiff).length > 0 ||
    isolationChanged || shellChanged || extraChanged;
  const poolInvalid =
    !Number.isInteger(pool.max_children) || pool.max_children < 1 || pool.max_children > POOL_MAX_CHILDREN ||
    !Number.isInteger(pool.max_requests) || pool.max_requests < 0 || pool.max_requests > 100000 ||
    !Number.isInteger(pool.idle_timeout_s) || pool.idle_timeout_s < 1 || pool.idle_timeout_s > 3600 ||
    !Number.isInteger(pool.request_terminate_timeout_s) || pool.request_terminate_timeout_s < 0 ||
    pool.request_terminate_timeout_s > 86400;
  const invalid =
    Object.keys(fieldErrors).length > 0 ||
    (data.can_admin && (poolInvalid || extraErrors.some((e) => e != null)));

  const setEdit = (key: string, v: string | null) => {
    setEdits((prev) => ({ ...prev, [key]: v }));
    if (serverField === key) setServerField(null);
  };

  const discard = () => { adopt(data); setMessage(null); };

  const save = async () => {
    const body: PhpSettingsUpdate = {};
    if (Object.keys(valuesDiff).length > 0) body.values = valuesDiff;
    // An owner sending any other key gets a 403 (B2): only add what changed,
    // and only when the server says this caller may.
    if (data.can_admin) {
      if (isolationChanged) body.isolation = isolation;
      if (shellChanged) body.disable_shell = disableShell;
      if (Object.keys(poolDiff).length > 0) body.pool = poolDiff;
      if (extraChanged) body.extra = cleanedExtra;
    }
    setSaving(true);
    setMessage(null);
    setServerField(null);
    try {
      const updated = await api.put<PhpSettingsResponse>(`/sites/${siteId}/php-settings`, body);
      adopt(updated);
      setMessage({ text: "PHP settings saved and applied", error: false });
      onSaved?.();
    } catch (e) {
      const field = e instanceof ApiError ? (e.body?.field as string | undefined) : undefined;
      setServerField(field && typeof field === "string" ? field : null);
      setMessage({ text: e instanceof Error ? e.message : "Save failed", error: true });
    } finally {
      setSaving(false);
    }
  };

  // Legacy site -> panel defaults (admin only). Unsaved edits are dropped: the
  // response replaces the whole card state.
  const usePanelDefaults = async () => {
    setConfirmPanelDefaults(false);
    setSaving(true);
    setMessage(null);
    setServerField(null);
    try {
      const body: PhpSettingsUpdate = { legacy: false };
      const updated = await api.put<PhpSettingsResponse>(`/sites/${siteId}/php-settings`, body);
      adopt(updated);
      setMessage({ text: "Panel defaults now apply to this site", error: false });
      onSaved?.();
    } catch (e) {
      setMessage({ text: e instanceof Error ? e.message : "Switch failed", error: true });
    } finally {
      setSaving(false);
    }
  };

  const inherited = new Set(data.inherits_global ?? []);
  const knownFieldKeys = new Set(data.fields.map((f) => f.key));
  const poolFieldError = serverField && !knownFieldKeys.has(serverField) ? serverField : null;

  const renderField = (f: PhpField) => {
    const own = valueOf(f.key);
    const def = data.defaults[f.key];
    const effective = own ?? def;
    const err = fieldErrors[f.key] || (serverField === f.key ? message?.text : undefined);
    const hasOverride = own != null;
    // Legacy site: no panel default for this key, resetting re-inherits php.ini.
    const inheritsIni = !hasOverride && inherited.has(f.key);
    const noPanelDefault = data.legacy === true && def == null;
    let control;
    if (f.kind === "bool") {
      control = (
        <OnOff
          value={effective == null ? null : effective === "On"}
          disabled={saving}
          onChange={(v) => setEdit(f.key, v ? "On" : "Off")}
        />
      );
    } else if (f.kind === "choice") {
      const choices = f.choices ?? [];
      const known = own == null || choices.some((c) => c.value === own);
      control = (
        <select
          value={own ?? ""}
          disabled={saving}
          onChange={(e) => setEdit(f.key, e.target.value === "" ? null : e.target.value)}
          className={err ? inputErrCls : inputCls}
        >
          <option value="">{noPanelDefault ? "Global php.ini (inherited)" : `Default (${defaultLabel(f, def)})`}</option>
          {!known && own != null && <option value={own}>{own}</option>}
          {choices.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      );
    } else {
      control = (
        <div className="relative">
          <input
            type="number"
            value={toInputText(f, own)}
            min={f.min}
            max={f.max}
            disabled={saving}
            placeholder={noPanelDefault ? INHERITED : toInputText(f, def)}
            onChange={(e) => setEdit(f.key, fromInputText(f, e.target.value))}
            className={`${err ? inputErrCls : inputCls} ${f.kind === "size" ? "pr-12" : ""}`}
          />
          {f.kind === "size" && (
            <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-dark-300 pointer-events-none">MB</span>
          )}
        </div>
      );
    }
    return (
      <div key={f.key}>
        <div className="flex items-center justify-between mb-1 gap-2">
          <label className="block text-xs font-medium text-dark-200">
            {f.label} <span className="font-mono text-dark-400 font-normal">{f.key}</span>
          </label>
          {hasOverride && (
            <button
              type="button"
              disabled={saving}
              onClick={() => setEdit(f.key, null)}
              className="text-[11px] text-accent-400 hover:text-accent-300 disabled:opacity-50"
              title={noPanelDefault ? "Inherit the value from the global php.ini" : "Use the default value"}
            >
              {noPanelDefault ? "Reset to php.ini" : "Reset to default"}
            </button>
          )}
        </div>
        {control}
        <p className={`text-[11px] mt-1 ${err ? "text-danger-400" : "text-dark-400"}`}>
          {err
            ? err
            : `${inheritsIni ? "Inherited from global php.ini" : noPanelDefault ? "Default: global php.ini" : `Default: ${defaultLabel(f, def)}`}${f.min != null || f.max != null ? ` · Range ${f.min ?? "…"}–${f.max ?? "…"}${f.kind === "size" ? " MB" : ""}` : ""}${hasOverride ? " · overridden" : ""}`}
        </p>
      </div>
    );
  };

  const setPoolNum = (k: keyof PhpPool, raw: string) => {
    const n = raw.trim() === "" ? NaN : Number(raw);
    setPool((p) => (p ? { ...p, [k]: n } : p));
  };
  const poolNum = (n: number) => (Number.isFinite(n) ? String(n) : "");

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
      <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between gap-3">
        <h2 className={sectionTitle}>PHP Settings</h2>
        {data.php_version && (
          <span className="text-xs text-dark-300 font-mono">PHP {data.php_version}</span>
        )}
      </div>
      <div className="p-5 space-y-6">
        <p className="text-xs text-dark-300">
          Applied to this site's PHP-FPM pool. Leave a field empty to use the default. These values take
          priority over the server's global php.ini. PHP memory and workers are also shown in Resource Limits —
          both cards stay in sync.
        </p>

        {data.legacy && (
          <div className="rounded-lg border border-warn-500/40 bg-warn-500/5 px-4 py-3 text-xs text-dark-200 flex flex-col sm:flex-row sm:items-center gap-3">
            <p className="flex-1">
              This site was created before per-site PHP settings and keeps its previous behaviour: only the
              overridden values are applied, the others are inherited from the global php.ini
              {data.php_version ? ` of PHP ${data.php_version}` : ""}.
            </p>
            {data.can_admin && (
              <button
                type="button"
                disabled={saving}
                onClick={() => setConfirmPanelDefaults(true)}
                className={btnSecondary}
              >
                Use panel defaults
              </button>
            )}
          </div>
        )}
        {confirmPanelDefaults && (
          <ConfirmDialog
            label="Switch this site to the panel defaults? Values currently inherited from the global php.ini (timezone, error display, input limits, session lifetime...) will be replaced by the panel defaults. Current overrides are kept; unsaved changes in this card are discarded."
            confirmLabel="Use panel defaults"
            tone="warn"
            onConfirm={usePanelDefaults}
            onCancel={() => setConfirmPanelDefaults(false)}
          />
        )}

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {data.fields.map(renderField)}
        </div>

        {data.can_admin && (
          <>
            {/* Isolation & security */}
            <div className="border-t border-dark-600 pt-5 space-y-4">
              <h3 className={sectionTitle}>Isolation &amp; Security</h3>
              <div className="flex flex-col sm:flex-row sm:items-start gap-3 sm:gap-6">
                <div className="shrink-0">
                  <OnOff value={isolation} disabled={saving} onChange={setIsolation} labels={["Isolated", "Off"]} />
                </div>
                <div className="text-xs text-dark-300 space-y-1">
                  <p className="text-dark-100 font-medium">Site isolation</p>
                  <p>
                    Restricts PHP to the site's folder (<span className="font-mono">open_basedir</span> = the site
                    directory, its <span className="font-mono">tmp</span>, <span className="font-mono">/tmp</span> and{" "}
                    <span className="font-mono">/usr/share/php</span>), stores uploads and sessions in a private
                    per-site <span className="font-mono">tmp</span> folder, and sends mail as{" "}
                    <span className="font-mono">noreply@</span>the domain via sendmail.
                  </p>
                </div>
              </div>
              <div className="flex flex-col sm:flex-row sm:items-start gap-3 sm:gap-6">
                <div className="shrink-0">
                  <OnOff value={disableShell} disabled={saving} onChange={setDisableShell} labels={["Blocked", "Allowed"]} />
                </div>
                <div className="text-xs text-dark-300 space-y-1">
                  <p className="text-dark-100 font-medium">Shell functions</p>
                  <p>
                    When blocked, PHP cannot run these functions:{" "}
                    {SHELL_FUNCTIONS.map((fn, i) => (
                      <span key={fn}>
                        <span className="font-mono text-dark-100">{fn}</span>
                        {i < SHELL_FUNCTIONS.length - 1 ? ", " : ""}
                      </span>
                    ))}
                    . Some plugins (image tools, backups, Composer) need them.
                  </p>
                </div>
              </div>
            </div>

            {/* Pool */}
            <div className="border-t border-dark-600 pt-5 space-y-4">
              <h3 className={sectionTitle}>Pool</h3>
              {poolFieldError && (
                <p className="text-xs text-danger-400">
                  <span className="font-mono">{poolFieldError}</span>: {message?.text}
                </p>
              )}
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4">
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Process manager</label>
                  <select
                    value={pool.pm}
                    disabled={saving}
                    onChange={(e) => setPool((p) => (p ? { ...p, pm: e.target.value as PhpPool["pm"] } : p))}
                    className={inputCls}
                  >
                    <option value="ondemand">ondemand</option>
                    <option value="dynamic">dynamic</option>
                    <option value="static">static</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Max children</label>
                  <input type="number" min={1} max={POOL_MAX_CHILDREN} disabled={saving} value={poolNum(pool.max_children)}
                    onChange={(e) => setPoolNum("max_children", e.target.value)} className={inputCls} />
                  <p className="text-[11px] mt-1 text-dark-400">1–{POOL_MAX_CHILDREN} · = PHP workers</p>
                </div>
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Max requests</label>
                  <input type="number" min={0} max={100000} disabled={saving} value={poolNum(pool.max_requests)}
                    onChange={(e) => setPoolNum("max_requests", e.target.value)} className={inputCls} />
                  <p className="text-[11px] mt-1 text-dark-400">0–100000 · 0 = never recycle</p>
                </div>
                {pool.pm === "ondemand" && (
                  <div>
                    <label className="block text-xs font-medium text-dark-200 mb-1">Idle timeout (s)</label>
                    <input type="number" min={1} max={3600} disabled={saving} value={poolNum(pool.idle_timeout_s)}
                      onChange={(e) => setPoolNum("idle_timeout_s", e.target.value)} className={inputCls} />
                    <p className="text-[11px] mt-1 text-dark-400">1–3600</p>
                  </div>
                )}
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Request timeout (s)</label>
                  <input type="number" min={0} max={86400} disabled={saving} value={poolNum(pool.request_terminate_timeout_s)}
                    onChange={(e) => setPoolNum("request_terminate_timeout_s", e.target.value)} className={inputCls} />
                  <p className="text-[11px] mt-1 text-dark-400">0–86400 · also the nginx read timeout</p>
                </div>
              </div>
              {poolInvalid && <p className="text-xs text-danger-400">A pool value is empty or out of range.</p>}
            </div>

            {/* Extra directives */}
            <div className="border-t border-dark-600 pt-5 space-y-3">
              <div className="flex items-center justify-between">
                <h3 className={sectionTitle}>Extra Directives</h3>
                <button
                  type="button"
                  disabled={saving}
                  onClick={() => setExtra((rows) => [...rows, ["", ""]])}
                  className="text-xs text-accent-400 hover:text-accent-300 disabled:opacity-50"
                >
                  + Add directive
                </button>
              </div>
              <p className="text-xs text-dark-300">
                Written as <span className="font-mono">php_value[key] = value</span>. Security keys
                (open_basedir, disable_functions, extension…) cannot be set here.
              </p>
              {extra.length === 0 && <p className="text-xs text-dark-400">No extra directive.</p>}
              {extra.map(([k, v], i) => (
                <div key={i}>
                  <div className="flex items-center gap-2">
                    <input
                      value={k}
                      disabled={saving}
                      placeholder="opcache.memory_consumption"
                      spellCheck={false}
                      onChange={(e) => setExtra((rows) => rows.map((r, j) => (j === i ? [e.target.value, r[1]] : r)))}
                      className={`${extraErrors[i] ? inputErrCls : inputCls} font-mono`}
                    />
                    <span className="text-dark-400">=</span>
                    <input
                      value={v}
                      disabled={saving}
                      placeholder="256"
                      spellCheck={false}
                      onChange={(e) => setExtra((rows) => rows.map((r, j) => (j === i ? [r[0], e.target.value] : r)))}
                      className={`${extraErrors[i] ? inputErrCls : inputCls} font-mono`}
                    />
                    <button
                      type="button"
                      disabled={saving}
                      onClick={() => setExtra((rows) => rows.filter((_, j) => j !== i))}
                      className="px-2 py-2 text-dark-300 hover:text-danger-400 disabled:opacity-50"
                      aria-label="Remove directive"
                      title="Remove"
                    >
                      <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  {extraErrors[i] && <p className="text-[11px] mt-1 text-danger-400">{extraErrors[i]}</p>}
                </div>
              ))}
            </div>
          </>
        )}

        <div className="flex flex-wrap items-center justify-end gap-3 border-t border-dark-600 pt-4">
          {message && (
            <span className={`text-xs ${message.error ? "text-danger-400" : "text-rust-400"}`}>{message.text}</span>
          )}
          {dirty && (
            <button type="button" disabled={saving} onClick={discard} className={btnSecondary}>Discard</button>
          )}
          <button type="button" disabled={saving || !dirty || invalid} onClick={save} className={btnPrimary}>
            {saving ? "Applying..." : "Save PHP Settings"}
          </button>
        </div>
      </div>
    </div>
  );
}
