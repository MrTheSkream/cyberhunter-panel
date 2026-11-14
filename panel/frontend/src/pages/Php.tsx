import { useCallback, useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useServer } from "../context/ServerContext";
import { api } from "../api";
import ConfirmDialog from "../components/ConfirmDialog";
import {
  type PhpIniResponse,
  PHP_INI_KEYS,
  PHP_INI_MAX_BYTES,
  changedIniValues,
  utf8Bytes,
  validateIniValue,
} from "../utils/phpSettings";

interface PhpVersion {
  version: string;
  installed: boolean;
  fpm_running: boolean;
  socket: string;
}

const inputCls =
  "w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none";
const inputErrCls =
  "w-full px-3 py-2 border border-danger-500 rounded-lg text-sm focus:ring-2 focus:ring-danger-500 focus:border-danger-500 outline-none";
const btnPrimary =
  "px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors";
const btnSecondary =
  "px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 disabled:opacity-50 transition-colors";
const sectionTitle = "text-xs font-medium text-dark-300 uppercase font-mono tracking-widest";

function draftFrom(d: PhpIniResponse): Record<string, string> {
  const out: Record<string, string> = {};
  for (const { key } of PHP_INI_KEYS) out[key] = d.values[key] ?? "";
  return out;
}

/**
 * Admin page "PHP": the global PHP-FPM php.ini of each installed version
 * (contract A2/A3/B3). The CLI php.ini is never touched; per-site settings
 * still take priority over what is set here.
 */
export default function Php() {
  const { user } = useAuth();
  const { activeServerId } = useServer();
  const isAdmin = user?.role === "admin";
  const [versions, setVersions] = useState<PhpVersion[]>([]);
  const [versionsError, setVersionsError] = useState("");
  const [version, setVersion] = useState("");
  const [data, setData] = useState<PhpIniResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadError, setLoadError] = useState("");
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [raw, setRaw] = useState("");
  const [saving, setSaving] = useState<"values" | "file" | null>(null);
  const [success, setSuccess] = useState("");
  const [agentError, setAgentError] = useState("");
  const [confirmFile, setConfirmFile] = useState(false);

  const adopt = (d: PhpIniResponse) => {
    setData(d);
    setDraft(draftFrom(d));
    setRaw(d.content);
  };

  // Versions installed on the active server.
  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    setVersionsError("");
    api
      .get<{ versions: PhpVersion[] }>("/php/versions")
      .then((res) => {
        if (cancelled) return;
        const installed = (res.versions ?? []).filter((v) => v.installed);
        setVersions(installed);
        setVersion((cur) => (installed.some((v) => v.version === cur) ? cur : installed[0]?.version ?? ""));
      })
      .catch((e) => {
        if (cancelled) return;
        setVersions([]);
        setVersion("");
        setVersionsError(e instanceof Error ? e.message : "Could not list PHP versions");
      });
    return () => { cancelled = true; };
  }, [isAdmin, activeServerId]);

  const load = useCallback(async (v: string) => {
    setLoading(true);
    setLoadError("");
    setSuccess("");
    setAgentError("");
    try {
      adopt(await api.get<PhpIniResponse>(`/php/ini/${encodeURIComponent(v)}`));
    } catch (e) {
      setData(null);
      setLoadError(e instanceof Error ? e.message : "Could not read php.ini");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!isAdmin || !version) { setData(null); return; }
    load(version);
  }, [isAdmin, version, activeServerId, load]);

  if (!isAdmin) return <Navigate to="/" replace />;

  const valuesDiff = data ? changedIniValues(data.values, draft) : {};
  const valuesDirty = Object.keys(valuesDiff).length > 0;
  const rawDirty = data != null && raw !== data.content;
  const valueErrors: Record<string, string> = {};
  for (const { key } of PHP_INI_KEYS) {
    const v = draft[key] ?? "";
    // An empty field is "leave as is" (never sent), not an error.
    if (v.trim() === "") continue;
    const err = validateIniValue(v);
    if (err) valueErrors[key] = err;
  }
  const rawBytes = utf8Bytes(raw);
  const rawTooBig = rawBytes > PHP_INI_MAX_BYTES;

  const put = async (kind: "values" | "file", body: { values: Record<string, string> } | { content: string }) => {
    if (!data) return;
    setSaving(kind);
    setSuccess("");
    setAgentError("");
    try {
      // Both editors show the same file: take both back from the response so a
      // later save of the other one cannot write stale content.
      adopt(await api.put<PhpIniResponse>(`/php/ini/${encodeURIComponent(data.version)}`, body));
      setSuccess(kind === "values" ? `Values saved — PHP ${data.version} FPM restarted` : `php.ini saved — PHP ${data.version} FPM restarted`);
    } catch (e) {
      setAgentError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(null);
    }
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-dark-50">PHP</h1>
          <p className="text-sm text-dark-300 mt-1">Global PHP-FPM php.ini, per installed version</p>
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="php-version" className="text-xs text-dark-300">Version</label>
          <select
            id="php-version"
            value={version}
            disabled={saving != null || versions.length === 0}
            onChange={(e) => {
              if ((valuesDirty || rawDirty) && !window.confirm("Discard unsaved changes?")) return;
              setVersion(e.target.value);
            }}
            className="px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
          >
            {versions.length === 0 && <option value="">—</option>}
            {versions.map((v) => (
              <option key={v.version} value={v.version}>
                PHP {v.version}{v.fpm_running ? "" : " (FPM stopped)"}
              </option>
            ))}
          </select>
        </div>
      </div>

      <div className="px-4 py-3 rounded-lg text-sm border bg-accent-500/10 text-accent-400 border-accent-500/20">
        Settings defined on a site (Sites → site → PHP Settings) override this file for that site. Changes here apply
        to sites that do not set their own value. The CLI php.ini is not modified.
      </div>

      {versionsError && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20">{versionsError}</div>
      )}
      {!versionsError && versions.length === 0 && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-dark-800 text-dark-300 border-dark-500">
          No PHP version is installed on this server.
        </div>
      )}
      {loadError && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20">{loadError}</div>
      )}
      {success && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-rust-500/10 text-rust-400 border-rust-500/20">{success}</div>
      )}
      {agentError && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20">
          <p className="font-medium">The change was refused and the previous php.ini was kept.</p>
          <pre className="mt-2 text-xs font-mono whitespace-pre-wrap break-words text-danger-300 max-h-64 overflow-auto">{agentError}</pre>
        </div>
      )}

      {loading && !data && <div className="text-sm text-dark-300">Loading...</div>}

      {data && (
        <>
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
            <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between gap-3">
              <h2 className={sectionTitle}>Main Settings</h2>
              <span className="text-xs text-dark-300 font-mono">{data.path}</span>
            </div>
            <div className="p-5 space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {PHP_INI_KEYS.map(({ key, label, hint }) => (
                  <div key={key}>
                    <label className="block text-xs font-medium text-dark-200 mb-1">
                      {label} <span className="font-mono text-dark-400 font-normal">{key}</span>
                    </label>
                    <input
                      value={draft[key] ?? ""}
                      disabled={saving != null}
                      spellCheck={false}
                      placeholder={data.values[key] == null ? "not set" : ""}
                      onChange={(e) => setDraft((d) => ({ ...d, [key]: e.target.value }))}
                      className={`${valueErrors[key] ? inputErrCls : inputCls} font-mono`}
                    />
                    <p className={`text-[11px] mt-1 ${valueErrors[key] ? "text-danger-400" : "text-dark-400"}`}>
                      {valueErrors[key] ?? (data.values[key] == null ? `Not set in the file · ${hint}` : hint)}
                    </p>
                  </div>
                ))}
              </div>
              <div className="flex flex-wrap items-center justify-end gap-3">
                {rawDirty && (
                  <span className="text-xs text-warn-400">The file editor below has unsaved changes — save or discard them first.</span>
                )}
                {valuesDirty && (
                  <button type="button" disabled={saving != null} onClick={() => setDraft(draftFrom(data))} className={btnSecondary}>
                    Discard
                  </button>
                )}
                <button
                  type="button"
                  disabled={saving != null || !valuesDirty || rawDirty || Object.keys(valueErrors).length > 0}
                  onClick={() => put("values", { values: valuesDiff })}
                  className={btnPrimary}
                >
                  {saving === "values" ? "Applying..." : "Save values"}
                </button>
              </div>
            </div>
          </div>

          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
            <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between gap-3">
              <h2 className={sectionTitle}>php.ini File</h2>
              <span className={`text-xs font-mono ${rawTooBig ? "text-danger-400" : "text-dark-300"}`}>
                {(rawBytes / 1024).toFixed(1)} / {PHP_INI_MAX_BYTES / 1024} KiB
              </span>
            </div>
            <div className="p-5 space-y-3">
              <textarea
                value={raw}
                disabled={saving != null}
                onChange={(e) => setRaw(e.target.value)}
                rows={24}
                spellCheck={false}
                className="w-full px-3 py-2 border border-dark-500 rounded-lg text-xs font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none resize-y"
              />
              <p className="text-[11px] text-dark-400">
                A backup is kept, the file is checked with <span className="font-mono">php-fpm{data.version} -t</span> and
                FPM is restarted. If the check or the restart fails, the previous file is restored.
              </p>
              <div className="flex flex-wrap items-center justify-end gap-3">
                {valuesDirty && (
                  <span className="text-xs text-warn-400">Main settings above have unsaved changes — save or discard them first.</span>
                )}
                {rawTooBig && <span className="text-xs text-danger-400">The file is larger than 512 KiB.</span>}
                {rawDirty && (
                  <button type="button" disabled={saving != null} onClick={() => setRaw(data.content)} className={btnSecondary}>
                    Discard
                  </button>
                )}
                <button
                  type="button"
                  disabled={saving != null || !rawDirty || valuesDirty || rawTooBig}
                  onClick={() => setConfirmFile(true)}
                  className={btnPrimary}
                >
                  {saving === "file" ? "Applying..." : "Save file"}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {confirmFile && data && (
        <ConfirmDialog
          label={`Replace ${data.path} and restart PHP ${data.version} FPM? Every site on this version is restarted.`}
          confirmLabel="Save file"
          tone="warn"
          onConfirm={() => { setConfirmFile(false); put("file", { content: raw }); }}
          onCancel={() => setConfirmFile(false)}
        />
      )}
    </div>
  );
}
