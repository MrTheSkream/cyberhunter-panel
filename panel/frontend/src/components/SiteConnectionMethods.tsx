import { useState, useEffect, useCallback, type ReactNode } from "react";
import { api } from "../api";

/**
 * `GET /api/sites/{id}/access-info`: how a site's account can really connect,
 * read by the agent from the live config (vsftpd.conf + allow-list, `sshd -T`
 * for the account). `password_login: null` means unknown, never "works".
 */
export interface SiteAccessInfo {
  username: string;
  sftp: {
    port: number | null;
    ports: number[];
    password_login: boolean | null;
    error: string | null;
  };
  /** null when the server's agent is too old to say. */
  ftps: {
    installed: boolean;
    running: boolean;
    /** The account is on /etc/dockpanel/ftp-users. */
    allowed: boolean;
    port?: number;
    passive_min?: number;
    passive_max?: number;
    cert_hostname?: string | null;
    cert_kind?: "letsencrypt" | "self_signed" | null;
  } | null;
}

/** Fetches the access facts while `enabled`; `refresh` re-reads them after a toggle. */
export function useSiteAccessInfo(siteId: string | undefined, enabled: boolean) {
  const [info, setInfo] = useState<SiteAccessInfo | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const refresh = useCallback(async () => {
    if (!siteId) return;
    setLoading(true);
    try {
      setInfo(await api.get<SiteAccessInfo>(`/sites/${siteId}/access-info`));
      setError("");
    } catch (e) {
      setInfo(null);
      setError(e instanceof Error && e.message ? e.message : "Could not read the connection settings");
    } finally {
      setLoading(false);
    }
  }, [siteId]);

  useEffect(() => {
    if (!enabled) {
      setInfo(null);
      setError("");
      return;
    }
    refresh();
  }, [enabled, refresh]);

  return { info, error, loading, refresh };
}

function Field({ label, children, mono = true }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="text-dark-400 uppercase tracking-wide mb-1">{label}</div>
      <div className={`text-dark-100 break-all ${mono ? "font-mono" : ""}`}>{children}</div>
    </div>
  );
}

/** What the SFTP "Password login" field says. Pure, so the wording is easy to pin. */
export function sftpPasswordLabel(passwordLogin: boolean | null): string {
  if (passwordLogin === true) return "Yes (same password)";
  if (passwordLogin === false) return "No - key only";
  return "Unknown";
}

export default function SiteConnectionMethods({
  domain,
  username,
  info,
  error,
  loading,
}: {
  domain: string;
  username: string;
  info: SiteAccessInfo | null;
  error: string;
  loading: boolean;
}) {
  const ftps = info?.ftps;
  const showFtps = ftps?.installed === true && ftps.allowed === true;
  const sftp = info?.sftp;
  const sftpPort = sftp?.port ?? null;
  const certHost = ftps?.cert_hostname ?? null;
  const certDiffers = certHost != null && certHost.toLowerCase() !== domain.toLowerCase();

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 gap-3 text-xs">
        <Field label="Username">{username}</Field>
        <Field label="Password" mono={false}>Set with Reset Password</Field>
      </div>
      <p className="text-xs text-dark-300">
        The same username and password (from Reset Password) are used for every connection method below.
      </p>

      {loading && !info && <p className="text-xs text-dark-400">Checking connection methods...</p>}
      {error && (
        <p className="text-xs px-3 py-2 rounded-lg bg-warn-500/10 text-warn-400 border border-warn-500/30">
          Could not read this server's connection settings: {error}
        </p>
      )}

      {showFtps && ftps && (
        <div className="bg-dark-900 rounded-lg border border-dark-600 p-4 space-y-3">
          <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">FTPS</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
            <Field label="Protocol" mono={false}>FTP with explicit TLS (FTPS)</Field>
            <Field label="Host">{domain}</Field>
            <Field label="Port">{ftps.port ?? 21}</Field>
            <Field label="Encryption" mono={false}>Require explicit FTP over TLS</Field>
            <Field label="Passive ports">
              {ftps.passive_min ?? 12000}-{ftps.passive_max ?? 12100}
            </Field>
            <Field label="Certificate">
              {certHost ?? "unknown"}
              {ftps.cert_kind === "self_signed" && <span className="font-sans text-dark-400"> (self-signed)</span>}
              {ftps.cert_kind === "letsencrypt" && <span className="font-sans text-dark-400"> (Let's Encrypt)</span>}
            </Field>
          </div>
          {!ftps.running && (
            <p className="text-xs text-warn-400">The FTP server is installed but not running right now.</p>
          )}
          {certDiffers && (
            <p className="text-xs text-dark-400">
              The server presents a certificate for <span className="font-mono">{certHost}</span>, not{" "}
              <span className="font-mono">{domain}</span>: FileZilla asks you to trust it on the first connection.
              {ftps.cert_kind !== "self_signed" && (
                <> Use <span className="font-mono">{certHost}</span> as the host to avoid that prompt.</>
              )}
            </p>
          )}
          {!certDiffers && ftps.cert_kind === "self_signed" && (
            <p className="text-xs text-dark-400">
              The certificate is self-signed: your FTP client asks you to trust it on the first connection.
            </p>
          )}
        </div>
      )}

      <div className="bg-dark-900 rounded-lg border border-dark-600 p-4 space-y-3">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">SFTP</h3>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 text-xs">
          <Field label="Protocol" mono={false}>SFTP (SSH)</Field>
          <Field label="Host">{domain}</Field>
          <Field label="Port">{sftpPort ?? "unknown"}</Field>
          <Field label="Password login" mono={false}>
            <span className={sftp?.password_login === false ? "text-warn-400" : undefined}>
              {sftpPasswordLabel(sftp?.password_login ?? null)}
            </span>
          </Field>
        </div>
        {sftp?.password_login === false && (
          <p className="text-xs text-warn-400">
            SSH password login is disabled for site accounts on this server: the password does not work over
            SFTP, only an SSH key does.{showFtps ? " Use FTPS above to connect with the password." : ""}
          </p>
        )}
        {sftp && sftp.password_login == null && (
          <p className="text-xs text-dark-400">
            This server did not say whether SSH password login is allowed for site accounts
            {sftp.error ? ` (${sftp.error})` : ""}. If the password is refused over SFTP, the account is key only.
          </p>
        )}
      </div>

      <p className="text-xs text-dark-400">
        You land in the account's root folder: the site files are in <span className="font-mono">content/</span>.
      </p>
    </div>
  );
}
