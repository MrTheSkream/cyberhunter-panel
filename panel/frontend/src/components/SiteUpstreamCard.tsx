import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

// Site detail -> Upstream, for reverse proxy sites only. The site keeps its own
// vhost (bound IP, aliases, certificate, canonical/HSTS); only the local port
// nginx proxies to changes. Two ways to set it:
// - follow a Git Deploy: the port becomes the deploy's host port, and the
//   link stops the port from being typed by hand;
// - type it, for an app the panel does not deploy.

/** One entry of `GET /sites/{id}/git-deploy`. */
interface Candidate {
  id: string;
  name: string;
  host_port: number;
  domain: string | null;
  status: string;
  linkable: boolean;
  /** Why it cannot be linked, when `linkable` is false. */
  reason: string | null;
}

interface LinkState {
  git_deploy_id: string | null;
  proxy_port: number | null;
  candidates: Candidate[];
}

interface Props {
  siteId: string;
  proxyPort: number | null;
  gitDeployId: string | null | undefined;
  /** Called with the new values so the page's copy of the site stays current. */
  onChange: (patch: { proxy_port: number | null; git_deploy_id: string | null }) => void;
}

const errText = (e: unknown, fallback: string) => (e instanceof Error && e.message ? e.message : fallback);

/** Field text -> port to send. `undefined` = invalid. */
function parsePort(v: string): number | undefined {
  const t = v.trim();
  if (!/^\d{1,5}$/.test(t)) return undefined;
  const n = parseInt(t, 10);
  return n >= 1024 && n <= 65535 ? n : undefined;
}

export default function SiteUpstreamCard({ siteId, proxyPort, gitDeployId, onChange }: Props) {
  const [state, setState] = useState<LinkState | null>(null);
  const [loadError, setLoadError] = useState("");
  const [choice, setChoice] = useState("");
  const [portField, setPortField] = useState(proxyPort != null ? String(proxyPort) : "");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ text: string; error: boolean } | null>(null);

  const load = useCallback(async () => {
    try {
      setState(await api.get<LinkState>(`/sites/${siteId}/git-deploy`));
      setLoadError("");
    } catch (e) {
      setLoadError(errText(e, "Could not load the Git Deploys"));
    }
  }, [siteId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { setPortField(proxyPort != null ? String(proxyPort) : ""); }, [proxyPort]);

  const linked = gitDeployId ? state?.candidates.find((c) => c.id === gitDeployId) : undefined;
  const linkable = (state?.candidates ?? []).filter((c) => c.linkable && c.id !== gitDeployId);
  const parsedPort = parsePort(portField);
  const portChanged = portField.trim() !== (proxyPort != null ? String(proxyPort) : "");

  const link = async (deployId: string | null) => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.put<{ git_deploy_id: string | null; proxy_port: number | null }>(
        `/sites/${siteId}/git-deploy`,
        { git_deploy_id: deployId },
      );
      onChange({ proxy_port: r.proxy_port, git_deploy_id: r.git_deploy_id });
      setChoice("");
      setMsg({
        text: deployId ? `Now proxying to port ${r.proxy_port}` : `Unlinked. The site still proxies to port ${r.proxy_port}`,
        error: false,
      });
      await load();
    } catch (e) {
      setMsg({ text: errText(e, "Could not change the link"), error: true });
    } finally {
      setBusy(false);
    }
  };

  const savePort = async () => {
    if (parsedPort === undefined) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await api.put<{ proxy_port: number }>(`/sites/${siteId}/proxy-port`, { proxy_port: parsedPort });
      onChange({ proxy_port: r.proxy_port, git_deploy_id: null });
      setMsg({ text: `Now proxying to port ${r.proxy_port}`, error: false });
    } catch (e) {
      setMsg({ text: errText(e, "Could not save the port"), error: true });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
      <div className="px-5 py-4 border-b border-dark-600">
        <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Upstream</h2>
      </div>
      <div className="p-5 space-y-4">
        <p className="text-sm text-dark-200">
          Proxies to <span className="font-mono text-dark-50">127.0.0.1:{proxyPort ?? "-"}</span>.
          Changing it keeps this site's IP, aliases, certificate and redirects.
        </p>

        {gitDeployId ? (
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-sm text-dark-100">
              Follows Git Deploy{" "}
              <Link to="/git-deploys" className="text-rust-400 hover:text-rust-300 font-medium">
                {linked?.name ?? gitDeployId}
              </Link>
              {linked && <span className="text-dark-300"> (port {linked.host_port}, {linked.status})</span>}
            </span>
            <button
              type="button"
              disabled={busy}
              onClick={() => link(gitDeployId)}
              className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded-lg text-xs font-medium hover:bg-dark-600 disabled:opacity-50"
            >
              Re-sync
            </button>
            <button
              type="button"
              disabled={busy}
              onClick={() => link(null)}
              className="px-3 py-1.5 rounded-lg border border-dark-600 text-xs text-dark-100 hover:text-dark-50 disabled:opacity-50"
            >
              Unlink
            </button>
          </div>
        ) : (
          <>
            <div className="flex items-end gap-3 flex-wrap">
              <div className="min-w-[14rem]">
                <label htmlFor="site-upstream-deploy" className="block text-xs font-medium text-dark-200 mb-1">
                  Follow a Git Deploy
                </label>
                <select
                  id="site-upstream-deploy"
                  value={choice}
                  onChange={(e) => setChoice(e.target.value)}
                  disabled={busy || linkable.length === 0}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 outline-none"
                >
                  <option value="">{linkable.length === 0 ? "No Git Deploy to link" : "Choose a Git Deploy"}</option>
                  {linkable.map((c) => (
                    <option key={c.id} value={c.id}>
                      {c.name} (port {c.host_port})
                    </option>
                  ))}
                </select>
              </div>
              <button
                type="button"
                disabled={busy || !choice}
                onClick={() => link(choice)}
                className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
              >
                Link
              </button>
            </div>
            {state && state.candidates.some((c) => !c.linkable) && (
              <ul className="text-xs text-dark-300 space-y-1">
                {state.candidates.filter((c) => !c.linkable).map((c) => (
                  <li key={c.id}>
                    <span className="font-mono">{c.name}</span>: {c.reason}
                  </li>
                ))}
              </ul>
            )}

            <div className="flex items-end gap-3 flex-wrap">
              <div className="max-w-[10rem]">
                <label htmlFor="site-upstream-port" className="block text-xs font-medium text-dark-200 mb-1">
                  Or set the port
                </label>
                <input
                  id="site-upstream-port"
                  type="text"
                  inputMode="numeric"
                  value={portField}
                  onChange={(e) => setPortField(e.target.value)}
                  autoComplete="off"
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                />
              </div>
              <button
                type="button"
                disabled={busy || !portChanged || parsedPort === undefined}
                onClick={savePort}
                className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50"
              >
                Save port
              </button>
            </div>
            {portChanged && parsedPort === undefined && (
              <p className="text-xs text-danger-400">A port between 1024 and 65535.</p>
            )}
          </>
        )}

        {loadError && <p className="text-xs text-danger-400">{loadError}</p>}
        {msg && <p className={`text-xs ${msg.error ? "text-danger-400" : "text-rust-400"}`}>{msg.text}</p>}
      </div>
    </div>
  );
}
