import { useState, useEffect, useCallback, useRef } from "react";
import { api, ApiError } from "../api";
import ProvisionLog from "./ProvisionLog";

/** The error code the backend relays when a site asks for Apache on a server without it. */
export const APACHE_NOT_INSTALLED = "apache_not_installed";

export const isApacheNotInstalled = (e: unknown) =>
  e instanceof ApiError && e.code === APACHE_NOT_INSTALLED;

/**
 * The error code the backend relays when Apache mode cannot be used on this
 * server at all (RHEL family today). There is nothing to install, so only
 * "nginx only" is offered.
 */
export const APACHE_UNSUPPORTED = "apache_unsupported";

export const isApacheUnsupported = (e: unknown) =>
  e instanceof ApiError && e.code === APACHE_UNSUPPORTED;

/** The one sentence every unsupported case shows. */
export const APACHE_UNSUPPORTED_MESSAGE = "Apache mode is not supported on this server.";

type InstallStatus = Record<
  string,
  { installed?: boolean; running?: boolean; supported?: boolean } | undefined
>;

/** What install-status says about Apache. `null` = unknown, not "no". */
export interface ApacheState {
  installed: boolean | null;
  supported: boolean | null;
}

/**
 * Whether Apache is installed, and whether it can be used at all, on this
 * server, from `/services/install-status`.
 *
 * That route is admin-only, so for everyone else - and whenever the agent cannot
 * be asked, or is a release behind and does not report `apache` - both answers
 * are `null`: unknown, not "missing". Only an explicit `installed: false` is
 * treated as missing and only an explicit `supported: false` as unsupported;
 * the server stays the authority and answers a create or a switch with
 * `apache_not_installed` / `apache_unsupported` when it really is.
 */
export function useApacheInstalled(enabled: boolean) {
  const [installed, setInstalled] = useState<boolean | null>(null);
  const [supported, setSupported] = useState<boolean | null>(null);

  const refresh = useCallback(async (): Promise<ApacheState> => {
    try {
      const s = await api.get<InstallStatus>("/services/install-status");
      const i = typeof s?.apache?.installed === "boolean" ? s.apache.installed : null;
      const sup = typeof s?.apache?.supported === "boolean" ? s.apache.supported : null;
      setInstalled(i);
      setSupported(sup);
      return { installed: i, supported: sup };
    } catch {
      setInstalled(null);
      setSupported(null);
      return { installed: null, supported: null };
    }
  }, []);

  useEffect(() => {
    if (enabled) refresh();
  }, [enabled, refresh]);

  return { installed, supported, refresh, setInstalled, setSupported };
}

/**
 * "Apache mode is not supported on this server" with nginx only as the way out.
 * Shown instead of the install callout: there is nothing to install (D1: the
 * choice is stated and offered, never made silently).
 */
export function ApacheUnsupportedNotice({
  onUseNginx,
  disabled,
}: {
  onUseNginx?: () => void;
  disabled?: boolean;
}) {
  return (
    <div className="px-3 py-2.5 bg-warn-500/10 border border-warn-500/30 rounded-lg space-y-2">
      <p className="text-xs text-warn-400">
        {APACHE_UNSUPPORTED_MESSAGE} The nginx + Apache mode cannot be used here, so .htaccess
        files would not be read.
      </p>
      {onUseNginx && (
        <button
          type="button"
          onClick={onUseNginx}
          disabled={disabled}
          className="px-3 py-1.5 border border-dark-600 text-dark-100 rounded-md text-xs font-medium hover:text-dark-50 hover:border-dark-500 disabled:opacity-50"
        >
          Use nginx only
        </button>
      )}
    </div>
  );
}

interface CalloutProps {
  /** Installing is admin-only server-side; a non-admin sees the state, not the button. */
  canInstall: boolean;
  /** Re-reads install-status; must resolve to the fresh Apache state. */
  recheck: () => Promise<ApacheState>;
  /** Called once Apache is really there (re-read from the server, not the log ending). */
  onInstalled: () => void;
  /** Offered as the explicit alternative - never a silent fallback. */
  onUseNginx?: () => void;
  /** What happens after the install, shown on the button ("Install Apache and create the site"). */
  installLabel?: string;
  disabled?: boolean;
}

/**
 * "Apache is not installed" with the install offered in place: the same
 * `/services/install/apache` route and install log as Settings -> Services.
 */
export function ApacheInstallCallout({
  canInstall,
  recheck,
  onInstalled,
  onUseNginx,
  installLabel = "Install Apache",
  disabled,
}: CalloutProps) {
  const [installing, setInstalling] = useState(false);
  const [installId, setInstallId] = useState<string | null>(null);
  const [error, setError] = useState("");
  // The install was refused because Apache cannot run on this server (the
  // agent's 501, seen through install-status `supported: false`). Never shown
  // as "still not installed": retrying cannot help.
  const [unsupported, setUnsupported] = useState(false);
  // ProvisionLog keeps the onComplete it was mounted with, so the parent's
  // continuation (a create or a switch) is read through a ref: the retry uses
  // the form as it is now, not as it was when the install started.
  const onInstalledRef = useRef(onInstalled);
  onInstalledRef.current = onInstalled;
  // One continuation per install, whichever of the log or the poll settles first.
  const settledRef = useRef(false);

  const finish = () => {
    if (settledRef.current) return;
    settledRef.current = true;
    setInstalling(false);
    setInstallId(null);
    onInstalledRef.current();
  };

  // ProvisionLog does not call onComplete when the stream dies after the first
  // step, which would leave "Installing..." up forever. The install runs on the
  // server regardless, so ask the server directly while one is in flight.
  useEffect(() => {
    if (!installing) return;
    const started = Date.now();
    const t = window.setInterval(async () => {
      const now = await recheck();
      if (now.installed === true) {
        window.clearInterval(t);
        finish();
      } else if (now.supported === false) {
        window.clearInterval(t);
        setInstalling(false);
        setUnsupported(true);
      } else if (Date.now() - started > 20 * 60 * 1000) {
        window.clearInterval(t);
        setInstalling(false);
        setError("Apache has not appeared after 20 minutes. Check the server's package manager and systemd logs.");
      }
    }, 10000);
    return () => window.clearInterval(t);
  }, [installing, recheck]);

  const settle = async () => {
    const now = await recheck();
    if (settledRef.current) return;
    if (now.installed === true) {
      finish();
      return;
    }
    setInstalling(false);
    if (now.supported === false) {
      setUnsupported(true);
      return;
    }
    // Leave the log up: it holds the only account of what went wrong.
    setError(
      now.installed === false
        ? "Apache is still not installed. Check the install log above, retry, or use nginx only."
        : "Could not confirm that Apache is installed. Retry, or use nginx only.",
    );
  };

  const handleInstall = async () => {
    setError("");
    settledRef.current = false;
    setInstalling(true);
    setInstallId(null);
    try {
      const res = await api.post<{ install_id?: string }>("/services/install/apache", {});
      if (res?.install_id) {
        setInstallId(res.install_id);
      } else {
        await settle();
      }
    } catch (e) {
      setInstalling(false);
      if (isApacheUnsupported(e) || (e instanceof ApiError && e.status === 501)) {
        setUnsupported(true);
        return;
      }
      setError(e instanceof Error ? e.message : "Could not start the install");
    }
  };

  if (unsupported) {
    return <ApacheUnsupportedNotice onUseNginx={onUseNginx} disabled={disabled} />;
  }

  return (
    <div className="px-3 py-2.5 bg-warn-500/10 border border-warn-500/30 rounded-lg space-y-2">
      <p className="text-xs text-warn-400">
        Apache is not installed on this server. The nginx + Apache mode needs it to read
        .htaccess files.
      </p>
      {!canInstall && (
        <p className="text-xs text-dark-300">Ask an administrator to install Apache, or use nginx only.</p>
      )}
      <div className="flex items-center gap-2 flex-wrap">
        {canInstall && (
          <button
            type="button"
            onClick={handleInstall}
            disabled={installing || disabled}
            className="px-3 py-1.5 bg-rust-500 text-dark-950 rounded-md text-xs font-bold hover:bg-rust-400 transition-colors disabled:opacity-50"
          >
            {installing ? "Installing..." : installLabel}
          </button>
        )}
        {onUseNginx && (
          <button
            type="button"
            onClick={onUseNginx}
            disabled={disabled}
            className="px-3 py-1.5 border border-dark-600 text-dark-100 rounded-md text-xs font-medium hover:text-dark-50 hover:border-dark-500 disabled:opacity-50"
          >
            Use nginx only
          </button>
        )}
      </div>
      {installId && (
        <div>
          {installing && (
            <p className="text-xs text-dark-300 mb-2">
              Installing Apache. It runs on the server, so leaving this page will not stop it.
            </p>
          )}
          <ProvisionLog sseUrl={`/api/services/install/${installId}/log`} onComplete={settle} />
        </div>
      )}
      {error && <p className="text-xs text-danger-400">{error}</p>}
    </div>
  );
}
