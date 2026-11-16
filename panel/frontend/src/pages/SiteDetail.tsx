import { useState, useEffect, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { api, ApiError } from "../api";
import { formatDate } from "../utils/format";
import { statusColors, runtimeLabelsDetailed as runtimeLabels } from "../constants";
import { PrereqCallout, useDnsPrereq, prereqBlocks } from "../components/Prerequisite";
import PhpVersionPicker from "../components/PhpVersionPicker";
import PhpSettingsCard from "../components/PhpSettingsCard";
import { SiteAntivirusStatus, SiteAntivirusDetections, type AvSiteStatus } from "../components/AntivirusTab";
import { useAuth } from "../context/AuthContext";
import { useServerIps, serverIpOptionLabel } from "../utils/serverIps";
import {
  ApacheInstallCallout,
  ApacheUnsupportedNotice,
  APACHE_UNSUPPORTED_MESSAGE,
  useApacheInstalled,
  isApacheNotInstalled,
  isApacheUnsupported,
} from "../components/ApacheInstall";

interface Site {
  id: string;
  /** Server the site lives on (null on old rows = the local server). */
  server_id?: string | null;
  domain: string;
  runtime: string;
  status: string;
  proxy_port: number | null;
  php_version: string | null;
  ssl_enabled: boolean;
  ssl_expiry: string | null;
  rate_limit: number | null;
  max_upload_mb: number;
  bandwidth_quota_mb: number | null;
  bandwidth_suspended_at: string | null;
  php_memory_mb: number;
  php_max_workers: number;
  custom_nginx: string | null;
  php_preset: string | null;
  parent_site_id: string | null;
  synced_at: string | null;
  enabled: boolean;
  fastcgi_cache: boolean;
  redis_cache: boolean;
  redis_db: number;
  waf_enabled: boolean;
  waf_mode: string;
  csp_policy: string | null;
  permissions_policy: string | null;
  bot_protection: string;
  sftp_enabled: boolean;
  sftp_uid: number | null;
  created_at: string;
  updated_at: string;
  /** Declared server IP the vhost listens on; null = the primary IP. */
  ip_id?: string | null;
  /** Effective IP of `ip_id`; null = primary IP. */
  bind_ip?: string | null;
  /** "apache" = nginx in front of Apache (.htaccess read). Absent on older backends = "nginx". */
  web_server?: "nginx" | "apache";
  // import-hestia (W3). All optional: an older backend omits them.
  /** Aliases as recorded in the database; null = not managed by the database yet. */
  aliases?: string[] | null;
  /** Name every other served name redirects to; null = no canonical redirect. */
  canonical_host?: "www" | "apex" | null;
  /** Folders under the document root where PHP is never executed; null = none. */
  php_no_exec_dirs?: string[] | null;
  /** Redirect HTTP to HTTPS when SSL is on. Absent = true. */
  force_ssl?: boolean;
  /** Send Strict-Transport-Security when SSL is on. Absent = true. */
  hsts?: boolean;
  /** Custom SFTP account name; null = the default `sftp<uid>`. */
  sftp_username?: string | null;
}

/** PHP branches past end of life (kept for imported sites). */
const LEGACY_PHP_VERSIONS = new Set(["5.6", "7.4"]);

/** Default "no PHP execution" folders, as the backend applies them for `dirs: "defaults"`. */
const DEFAULT_NO_EXEC_DIRS = [
  "/wp-content/uploads",
  "/sites/default/files",
  "/storage/app/public",
  "/uploads",
  "/upload",
];

/** Client-side mirror of the backend rule for a no-exec folder; returns an error or "". */
function validateNoExecDir(dir: string): string {
  if (!dir.startsWith("/")) return "Each folder must start with /";
  if (!/^\/[A-Za-z0-9_./-]*$/.test(dir)) return "Only letters, digits and _ . / - are allowed";
  if (dir.includes("..")) return "A folder cannot contain ..";
  return "";
}

/** SFTP account name rule (contract W4-S). */
const SFTP_USERNAME_RE = /^[a-z_][a-z0-9_.-]{0,31}$/;

type SiteLogType = "access" | "error" | "apache_error";

interface StagingInfo {
  exists: boolean;
  site?: Site;
  disk_usage_bytes?: number;
}

export default function SiteDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { user } = useAuth();
  /** Holds sites, cannot claim a new domain - see `domain_claim::ensure_claimable`. */
  const isClient = user?.role === "client";
  const [site, setSite] = useState<Site | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [deleting, setDeleting] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [provisioning, setProvisioning] = useState(false);
  const [sslMessage, setSslMessage] = useState("");
  const [sslMessageIsError, setSslMessageIsError] = useState(false);
  // Set only by the agent's `foreign_certificate` refusal - never inferred
  // from any other 4xx, so a DNS 412 or a rate limit never grows a "replace
  // it anyway" button that has no business next to it. `retry` re-issues the
  // exact same provision call with `force: true`, the only way this reaches
  // the wire (mirrors the CLI's `--force`).
  const [foreignCertRefusal, setForeignCertRefusal] = useState<{
    message: string;
    retry: () => Promise<void>;
  } | null>(null);
  const [forcingSsl, setForcingSsl] = useState(false);
  // Only run the DNS prerequisite while SSL is still unconfigured; a live cert
  // is proof enough that the domain resolves here. autoPoll covers propagation:
  // a blocking gate opens by itself once the record goes live.
  const {
    prereq: dnsPrereq,
    checking: dnsChecking,
    recheck: recheckDns,
  } = useDnsPrereq(site && !site.ssl_enabled ? site.domain : "", { autoPoll: true, debounceMs: 0 });
  const [switchingPhp, setSwitchingPhp] = useState(false);
  const [phpMessage, setPhpMessage] = useState("");
  // The backend's caveat on a switch to a legacy version; shown apart from the result.
  const [phpWarning, setPhpWarning] = useState("");
  // What the picker is showing, which is not the same as what the site runs:
  // an uninstalled version stays selected while its install callout is up, and
  // only becomes the site's version once the switch actually goes through.
  const [phpChoice, setPhpChoice] = useState("");
  // #99: which runtime the operator is proposing to switch to, or null when the
  // row is just displaying. Held separately from `phpChoice` so an abandoned
  // runtime switch cannot leave the PHP Version picker on a version the site is
  // not running.
  const [runtimeTarget, setRuntimeTarget] = useState<"static" | "php" | null>(null);
  const [runtimePhpChoice, setRuntimePhpChoice] = useState("8.3");
  // The picker reports whether the chosen version is actually installed AND its
  // FPM socket is running. Holding the switch back on `false` mirrors what the
  // PHP Version control already does for an existing PHP site; without it the
  // button fires a switch the agent then refuses. Defaults true, matching the
  // picker's own permissive fallback for a version it has no record of.
  const [runtimePhpReady, setRuntimePhpReady] = useState(true);
  const [switchingRuntime, setSwitchingRuntime] = useState(false);
  const [runtimeMessage, setRuntimeMessage] = useState("");
  const [savingLimits, setSavingLimits] = useState(false);
  // IP address card. `/server-ips` and `PUT /sites/{id}/ip` are admin routes.
  const isAdmin = user?.role === "admin";
  const { ips: serverIps, loaded: serverIpsLoaded } = useServerIps(isAdmin);
  // ClamAV (06-clamav): the header badge reports its status here so the
  // detections card below can show itself and re-read after a scan; an action
  // in the card bumps the key so the badge re-reads its threat count.
  const [avStatus, setAvStatus] = useState<AvSiteStatus | null>(null);
  const [avRefreshKey, setAvRefreshKey] = useState(0);
  const bumpAvStatus = useCallback(() => setAvRefreshKey((k) => k + 1), []);
  const [siteIpId, setSiteIpId] = useState("");
  const [savingIp, setSavingIp] = useState(false);
  const [ipMessage, setIpMessage] = useState<{ text: string; error: boolean } | null>(null);
  const [limitsMessage, setLimitsMessage] = useState("");
  const [rateLimit, setRateLimit] = useState<string>("");
  const [maxUpload, setMaxUpload] = useState("64");
  const [bandwidthQuota, setBandwidthQuota] = useState<string>("");
  const [bandwidthUsage, setBandwidthUsage] = useState<{
    used_bytes_this_month: number;
    year_month: string;
  } | null>(null);
  const [phpMemory, setPhpMemory] = useState("256");
  const [phpWorkers, setPhpWorkers] = useState("5");
  const [customNginx, setCustomNginx] = useState("");
  const [staging, setStaging] = useState<StagingInfo | null>(null);
  const [stagingLoading, setStagingLoading] = useState(false);
  const [stagingMessage, setStagingMessage] = useState("");
  const [stagingDomain, setStagingDomain] = useState("");
  const [pendingConfirm, setPendingConfirm] = useState<{ type: string; label: string } | null>(null);
  const [showStagingForm, setShowStagingForm] = useState(false);

  // Redirects
  const [redirects, setRedirects] = useState<{ source: string; target: string; type: string }[]>([]);
  const [redirectSource, setRedirectSource] = useState("");
  const [redirectTarget, setRedirectTarget] = useState("");
  const [redirectType, setRedirectType] = useState("301");
  const [redirectMsg, setRedirectMsg] = useState("");
  const [showRedirects, setShowRedirects] = useState(false);

  // Password Protection
  const [protectedPaths, setProtectedPaths] = useState<string[]>([]);
  const [protectedUsers, setProtectedUsers] = useState<string[]>([]);
  const [protectPath, setProtectPath] = useState("/");
  const [protectUser, setProtectUser] = useState("");
  const [protectPass, setProtectPass] = useState("");
  const [protectMsg, setProtectMsg] = useState("");
  const [showProtect, setShowProtect] = useState(false);

  // Domain Aliases
  const [aliases, setAliases] = useState<string[]>([]);
  const [newAlias, setNewAlias] = useState("");
  const [aliasMsg, setAliasMsg] = useState("");
  const [showAliases, setShowAliases] = useState(false);
  const [savingCanonical, setSavingCanonical] = useState(false);
  const [canonicalMsg, setCanonicalMsg] = useState<{ text: string; error: boolean } | null>(null);

  // PHP no-exec folders (edit buffer, saved explicitly)
  const [noExecDirs, setNoExecDirs] = useState<string[]>([]);
  const [newNoExecDir, setNewNoExecDir] = useState("");
  const [savingNoExec, setSavingNoExec] = useState(false);
  const [noExecMsg, setNoExecMsg] = useState<{ text: string; error: boolean } | null>(null);

  // SSL options (force HTTPS / HSTS)
  const [savingSslOpts, setSavingSslOpts] = useState(false);
  const [sslOptsMsg, setSslOptsMsg] = useState("");

  // Access Logs
  const [accessLogs, setAccessLogs] = useState("");
  const [errorLogs, setErrorLogs] = useState("");
  const [phpErrors, setPhpErrors] = useState("");
  const [apacheErrorLogs, setApacheErrorLogs] = useState("");
  const [logsLoading, setLogsLoading] = useState(false);
  const [showAccessLogs, setShowAccessLogs] = useState(false);
  const [logType, setLogType] = useState<SiteLogType | "php">("access");

  // Traffic Stats
  interface TrafficStats {
    requests: number;
    unique_ips: number;
    bandwidth_mb: string;
    top_pages?: { path: string; count: number }[];
    status_codes?: Record<string, number>;
  }
  const [stats, setStats] = useState<TrafficStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);
  const [showStats, setShowStats] = useState(false);

  // Health Check
  const [health, setHealth] = useState<{ healthy: boolean; status: number; response_time_ms: number } | null>(null);
  const [checkingHealth, setCheckingHealth] = useState(false);
  const [healthSummary, setHealthSummary] = useState<{
    ssl_status: { enabled: boolean; days_until_expiry: number | null };
    backup_freshness: { last_backup: string | null; hours_since: number | null };
    uptime: { status: string | null; response_time_ms: number | null; monitor_enabled: boolean };
    score: number;
  } | null>(null);

  // Site Cloning
  const [cloning, setCloning] = useState(false);
  const [cloneMsg, setCloneMsg] = useState("");
  const [showCloneInput, setShowCloneInput] = useState(false);
  const [cloneDomainValue, setCloneDomainValue] = useState("");
  const [showTransfer, setShowTransfer] = useState(false);
  const [transferEmail, setTransferEmail] = useState("");
  const [transferring, setTransferring] = useState(false);
  const [transferMsg, setTransferMsg] = useState("");
  const [transferTargets, setTransferTargets] = useState<{ id: string; email: string; role: string }[]>([]);

  // WHO ISSUED THE CERTIFICATE THIS SITE IS SERVING.
  //
  // The row used to name one specific CA for every enabled site - see the badge
  // below for the wording - including a site carrying a certificate the operator
  // uploaded from a commercial CA, and including one the panel had already
  // DECLINED to renew for precisely that reason. The backend has been able to answer this since
  // `foreign_cert_issuer` shipped; nothing ever asked it on the operator's
  // behalf.
  //
  // ⛔ "unknown" is a real answer and is rendered as the neutral "Enabled",
  // never as a CA name. An unreachable agent lands here, and so does a site
  // served by a zone WILDCARD (the agent reports `has_cert:false` for the
  // site's own name while the certificate sits under the zone's). Both hold a
  // real certificate; neither is evidence about who issued it.
  const [sslProvenance, setSslProvenance] = useState<{
    provenance: "foreign" | "dockpanel" | "unknown";
    issuer: string | null;
  } | null>(null);

  // Custom SSL Upload
  const [showSslUpload, setShowSslUpload] = useState(false);
  // The three specialist certificate routes stay behind a disclosure. Offering
  // four flat choices - one of them the bare protocol acronym "DNS-01 (CF)" -
  // asks the operator to pick between mechanisms at exactly the moment they
  // cannot know which applies (s252 F12).
  const [showSslOptions, setShowSslOptions] = useState(false);
  const [sslCert, setSslCert] = useState("");
  const [sslKey, setSslKey] = useState("");
  const [uploadingSsl, setUploadingSsl] = useState(false);

  // Site toggle (disable/enable)
  const [toggling, setToggling] = useState(false);

  // Domain rename
  const [showRename, setShowRename] = useState(false);
  const [newDomain, setNewDomain] = useState("");
  const [renaming, setRenaming] = useState(false);
  const [renameMsg, setRenameMsg] = useState("");

  // Web server (nginx only / nginx + Apache)
  const [webServerTarget, setWebServerTarget] = useState<"nginx" | "apache" | null>(null);
  const [webServerSwitching, setWebServerSwitching] = useState(false);
  const [webServerMsg, setWebServerMsg] = useState("");
  // The switch was refused with `apache_not_installed`: offer the install, then retry.
  const [webServerApacheMissing, setWebServerApacheMissing] = useState(false);
  // The switch was refused with `apache_unsupported`: nothing to install.
  const [webServerApacheUnsupported, setWebServerApacheUnsupported] = useState(false);
  // Read up front for any PHP site (admins only, the route is admin-only), so a
  // server that cannot run Apache disables the switch before it is tried.
  const apacheStatus = useApacheInstalled(user?.role === "admin" && site?.runtime === "php");

  // FastCGI Cache
  const [cacheToggling, setCacheToggling] = useState(false);
  const [cachePurging, setCachePurging] = useState(false);
  const [cacheMsg, setCacheMsg] = useState("");

  // Redis Cache
  const [redisToggling, setRedisToggling] = useState(false);
  const [redisPurging, setRedisPurging] = useState(false);
  const [redisMsg, setRedisMsg] = useState("");
  const [sftpToggling, setSftpToggling] = useState(false);
  const [sftpResetting, setSftpResetting] = useState(false);
  const [sftpMsg, setSftpMsg] = useState("");
  const [sftpPassword, setSftpPassword] = useState<string | null>(null);
  const [sftpUsername, setSftpUsername] = useState("");
  const [sftpWarning, setSftpWarning] = useState("");
  const [copied, setCopied] = useState("");

  const copyToClipboard = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    setCopied(label);
    setTimeout(() => setCopied(""), 2000);
  };

  // WAF
  const [wafToggling, setWafToggling] = useState(false);
  const [wafMsg, setWafMsg] = useState("");

  // Security Headers (CSP)
  const [cspPolicy, setCspPolicy] = useState("");
  const [permsPolicy, setPermsPolicy] = useState("");
  const [headersSaving, setHeadersSaving] = useState(false);
  const [headersMsg, setHeadersMsg] = useState("");

  // Bot Protection
  const [botMode, setBotMode] = useState("off");
  const [botSaving, setBotSaving] = useState(false);
  const [botMsg, setBotMsg] = useState("");

  // Image Optimization
  const [imgOptRunning, setImgOptRunning] = useState(false);
  const [imgOptResult, setImgOptResult] = useState<{ converted?: number; total_images?: number; saved_mb?: string; format?: string } | null>(null);
  const [wafLogs, setWafLogs] = useState<{ timestamp: string; client_ip: string; uri: string; rule_message: string; severity: string; action: string }[] | null>(null);
  const [wafLogsLoading, setWafLogsLoading] = useState(false);

  // PHP Extensions
  const [phpExts, setPhpExts] = useState<{ installed: string[]; available: string[] } | null>(null);
  const [phpExtsLoading, setPhpExtsLoading] = useState(false);
  const [showPhpExts, setShowPhpExts] = useState(false);
  const [installingExt, setInstallingExt] = useState<string | null>(null);
  // Rendered beside the extension list rather than reusing `phpMessage`, which
  // paints ~1500 lines higher up next to the PHP VERSION control. A message the
  // operator has to scroll to find is the defect #120 was filed for.
  const [extMessage, setExtMessage] = useState("");

  // Environment Variables
  const [envVars, setEnvVars] = useState<{ key: string; value: string }[]>([]);
  const [showEnvVars, setShowEnvVars] = useState(false);
  const [savingEnv, setSavingEnv] = useState(false);
  const [envMsg, setEnvMsg] = useState("");

  const fetchStaging = () => {
    api.get<StagingInfo>(`/sites/${id}/staging`).then(setStaging).catch(() => { /* no staging */ });
  };

  const executeConfirm = async () => {
    if (!pendingConfirm) return;
    const { type } = pendingConfirm;
    setPendingConfirm(null);
    setStagingLoading(true);
    setStagingMessage("");
    try {
      if (type === "staging_push") {
        await api.post(`/sites/${id}/staging/push`);
        setStagingMessage("Staging pushed to production");
      } else if (type === "staging_delete") {
        await api.delete(`/sites/${id}/staging`);
        setStaging({ exists: false });
        setStagingMessage("Staging deleted");
      } else if (type === "staging_create_db_ack") {
        await api.post(`/sites/${id}/staging`, {
          domain: stagingDomain || undefined,
          acknowledge_shared_database: true,
        });
        fetchStaging();
        setShowStagingForm(false);
        setStagingMessage("Staging environment created");
      }
    } catch (e) {
      setStagingMessage(e instanceof Error ? e.message : "Action failed");
    } finally {
      setStagingLoading(false);
    }
  };

  const loadRedirects = () => {
    api.get<{ redirects: { source: string; target: string; type: string }[] }>(`/sites/${id}/redirects`)
      .then((d) => setRedirects(d.redirects || []))
      .catch(() => {});
  };

  const loadProtected = () => {
    api.get<{ paths: string[]; users: string[] }>(`/sites/${id}/password-protect`)
      .then((d) => { setProtectedPaths(d.paths || []); setProtectedUsers(d.users || []); })
      .catch(() => {});
  };

  const switchWebServer = async (target: "nginx" | "apache") => {
    setWebServerSwitching(true);
    setWebServerMsg("");
    try {
      const res = await api.put<{ web_server: "nginx" | "apache" }>(`/sites/${id}/web-server`, {
        web_server: target,
      });
      const now = res?.web_server ?? target;
      setSite((s) => (s ? { ...s, web_server: now } : s));
      if (now !== "apache" && logType === "apache_error") setLogType("access");
      setWebServerTarget(null);
      setWebServerApacheMissing(false);
      setWebServerApacheUnsupported(false);
      setWebServerMsg(now === "apache" ? "Switched to nginx + Apache" : "Switched to nginx only");
    } catch (err) {
      if (isApacheUnsupported(err)) {
        // Nothing to install: say so and keep nginx only, without retrying.
        setWebServerApacheUnsupported(true);
        setWebServerApacheMissing(false);
      } else if (isApacheNotInstalled(err)) {
        setWebServerApacheMissing(true);
        apacheStatus.setInstalled(false);
      } else {
        setWebServerMsg(err instanceof Error ? err.message : "Switch failed");
      }
    } finally {
      setWebServerSwitching(false);
    }
  };

  const loadAliases = () => {
    api.get<{ aliases: string[] }>(`/sites/${id}/aliases`)
      .then((d) => setAliases(d.aliases || []))
      .catch(() => {});
  };

  const loadLogs = async (type: SiteLogType) => {
    setLogsLoading(true);
    try {
      const data = await api.get<{ logs: string }>(`/sites/${id}/access-logs?type=${type}&lines=200`);
      if (type === "access") setAccessLogs(data.logs);
      else if (type === "apache_error") setApacheErrorLogs(data.logs);
      else setErrorLogs(data.logs);
    } catch {}
    finally { setLogsLoading(false); }
  };

  const loadPhpErrors = async () => {
    setLogsLoading(true);
    try {
      const data = await api.get<{ logs: string }>(`/sites/${id}/php-errors`);
      setPhpErrors(data.logs);
    } catch {
      setPhpErrors("");
    } finally {
      setLogsLoading(false);
    }
  };

  const loadStats = async () => {
    setStatsLoading(true);
    try {
      const data = await api.get<TrafficStats>(`/sites/${id}/stats`);
      setStats(data);
    } catch {
      setStats(null);
    } finally {
      setStatsLoading(false);
    }
  };

  const loadPhpExtensions = async () => {
    if (!site?.php_version) return;
    setPhpExtsLoading(true);
    try {
      const data = await api.get<{ installed: string[]; available: string[] }>(`/php/extensions/${site.php_version}`);
      setPhpExts(data);
    } catch {
      setPhpExts(null);
    } finally {
      setPhpExtsLoading(false);
    }
  };

  const loadEnvVars = async () => {
    try {
      const data = await api.get<{ vars: { key: string; value: string }[] }>(`/sites/${id}/env`);
      setEnvVars(data.vars);
    } catch { setEnvVars([]); }
  };

  // Accounts a site can be handed to. Admin-only endpoint, and Transfer is
  // admin-only too, so this exposes nothing the caller could not already read.
  useEffect(() => {
    if (user?.role !== "admin") return;
    api
      .get<{ id: string; email: string; role: string }[]>("/users")
      .then((rows) => setTransferTargets(rows.filter((u) => u.role !== "suspended" && u.id !== user?.id)))
      .catch(() => setTransferTargets([]));
  }, [user?.role, user?.id]);

  // Ask WHO issued it, and only when there is something to ask about.
  //
  // ⚠ This costs an agent hop (`GET /api/sites/{id}/ssl` reaches the box), so it
  // is fired only for an SSL-enabled site and it NEVER blocks the row: until it
  // answers, `sslProvenance` is null and the badge renders the neutral wording.
  // A failure is left as null for the same reason - a page that cannot reach the
  // agent must not therefore start asserting a CA.
  const loadSslProvenance = useCallback(() => {
    api
      .get<{ provenance: "foreign" | "dockpanel" | "unknown"; issuer: string | null }>(
        `/sites/${id}/ssl`,
      )
      .then((r) => setSslProvenance({ provenance: r.provenance, issuer: r.issuer }))
      .catch(() => setSslProvenance(null));
  }, [id]);

  useEffect(() => {
    if (!site?.ssl_enabled) {
      setSslProvenance(null);
      return;
    }
    loadSslProvenance();
  }, [site?.ssl_enabled, site?.domain, loadSslProvenance]);

  // Composite score augmenting the plain up/down Health Check button above -
  // computed server-side from SSL expiry + backup freshness + monitor uptime,
  // not a replacement for the on-demand check.
  useEffect(() => {
    api
      .get<{
        ssl_status: { enabled: boolean; days_until_expiry: number | null };
        backup_freshness: { last_backup: string | null; hours_since: number | null };
        uptime: { status: string | null; response_time_ms: number | null; monitor_enabled: boolean };
        score: number;
      }>(`/sites/${id}/health-summary`)
      .then(setHealthSummary)
      .catch(() => setHealthSummary(null));
  }, [id]);

  useEffect(() => {
    api
      .get<Site>(`/sites/${id}`)
      .then((s) => {
        setSite(s);
        setRateLimit(s.rate_limit != null ? String(s.rate_limit) : "");
        setMaxUpload(String(s.max_upload_mb));
        setPhpMemory(String(s.php_memory_mb));
        setPhpWorkers(String(s.php_max_workers));
        setCustomNginx(s.custom_nginx || "");
        setCspPolicy(s.csp_policy || "");
        setPermsPolicy(s.permissions_policy || "");
        setBotMode(s.bot_protection || "off");
        setBandwidthQuota(s.bandwidth_quota_mb != null ? String(s.bandwidth_quota_mb) : "");
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
    fetchStaging();
    loadRedirects();
    loadProtected();
    loadAliases();
    api
      .get<{ used_bytes_this_month: number; year_month: string }>(`/sites/${id}/bandwidth-usage`)
      .then(setBandwidthUsage)
      .catch(() => setBandwidthUsage(null));
  }, [id]);

  const handleDelete = async () => {
    if (!confirmDelete) {
      setConfirmDelete(true);
      return;
    }
    setDeleting(true);
    try {
      await api.delete(`/sites/${id}`);
      navigate("/sites");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
      setDeleting(false);
    }
  };

  const handleProvisionSSL = async (force = false) => {
    if (!site) return;
    if (force) setForcingSsl(true); else setProvisioning(true);
    setSslMessage("");
    setForeignCertRefusal(null);
    try {
      await api.post(`/sites/${id}/ssl${force ? "?force=true" : ""}`);
      const updated = await api.get<Site>(`/sites/${id}`);
      setSite(updated);
      setSslMessage("SSL certificate provisioned successfully!");
      setSslMessageIsError(false);
    } catch (err) {
      if (err instanceof ApiError && err.code === "foreign_certificate") {
        setForeignCertRefusal({
          message: err.message,
          retry: () => handleProvisionSSL(true),
        });
      } else {
        setSslMessage(
          err instanceof Error ? err.message : "SSL provisioning failed"
        );
        setSslMessageIsError(true);
        // The server may have refused on a prerequisite (a 412 naming the DNS
        // problem). Refresh it so the callout beside the button reflects why.
        recheckDns();
      }
    } finally {
      if (force) setForcingSsl(false); else setProvisioning(false);
    }
  };

  const [dns01Loading, setDns01Loading] = useState(false);

  const handleProvisionDns01 = async (wildcard: boolean, force = false) => {
    if (!site) return;
    if (force) setForcingSsl(true); else setDns01Loading(true);
    setSslMessage("");
    setForeignCertRefusal(null);
    try {
      await api.post(`/sites/${id}/ssl/dns01`, { wildcard, force });
      const updated = await api.get<Site>(`/sites/${id}`);
      setSite(updated);
      setSslMessage(wildcard
        ? "Wildcard SSL certificate provisioned via DNS-01!"
        : "SSL certificate provisioned via DNS-01!"
      );
      setSslMessageIsError(false);
    } catch (err) {
      if (err instanceof ApiError && err.code === "foreign_certificate") {
        setForeignCertRefusal({
          message: err.message,
          retry: () => handleProvisionDns01(wildcard, true),
        });
      } else {
        setSslMessage(err instanceof Error ? err.message : "DNS-01 provisioning failed");
        setSslMessageIsError(true);
      }
    } finally {
      if (force) setForcingSsl(false); else setDns01Loading(false);
    }
  };

  // Reset the no-exec edit buffer to what the server holds whenever that changes.
  const savedNoExecKey = JSON.stringify(site?.php_no_exec_dirs ?? null);
  useEffect(() => {
    setNoExecDirs(site?.php_no_exec_dirs ?? []);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [site?.id, savedNoExecKey]);

  const saveNoExec = async (dirs: string[] | null | "defaults", okText: string) => {
    setSavingNoExec(true);
    setNoExecMsg(null);
    try {
      const res = await api.put<{ ok: boolean; php_no_exec_dirs: string[] | null }>(
        `/sites/${id}/php-no-exec`,
        { dirs },
      );
      setSite((s) => (s ? { ...s, php_no_exec_dirs: res.php_no_exec_dirs } : s));
      setNoExecDirs(res.php_no_exec_dirs ?? []);
      setNoExecMsg({ text: okText, error: false });
    } catch (e) {
      setNoExecMsg({ text: e instanceof Error ? e.message : "Save failed", error: true });
    } finally {
      setSavingNoExec(false);
    }
  };

  const saveSslOptions = async (next: { force_ssl: boolean; hsts: boolean }) => {
    if (!site) return;
    const prev = { force_ssl: site.force_ssl ?? true, hsts: site.hsts ?? true };
    setSavingSslOpts(true);
    setSslOptsMsg("");
    // Optimistic: the switch moves at once and moves back if the server refuses.
    setSite((s) => (s ? { ...s, ...next } : s));
    try {
      const res = await api.put<{ ok: boolean; force_ssl: boolean; hsts: boolean }>(
        `/sites/${id}/ssl-options`,
        next,
      );
      setSite((s) => (s ? { ...s, force_ssl: res.force_ssl, hsts: res.hsts } : s));
    } catch (e) {
      setSite((s) => (s ? { ...s, ...prev } : s));
      setSslOptsMsg(e instanceof Error ? e.message : "Could not save the SSL options");
    } finally {
      setSavingSslOpts(false);
    }
  };

  const setCanonicalHost = async (value: "www" | "apex" | null) => {
    setSavingCanonical(true);
    setCanonicalMsg(null);
    try {
      const res = await api.put<{ ok: boolean; canonical_host: "www" | "apex" | null }>(
        `/sites/${id}/canonical-host`,
        { canonical_host: value },
      );
      setSite((s) => (s ? { ...s, canonical_host: res.canonical_host } : s));
      setCanonicalMsg({
        text: res.canonical_host ? "Canonical host saved" : "Canonical redirect removed",
        error: false,
      });
    } catch (e) {
      setCanonicalMsg({ text: e instanceof Error ? e.message : "Save failed", error: true });
    } finally {
      setSavingCanonical(false);
    }
  };

  // Keep the IP select on the site's current value whenever it is (re)loaded.
  useEffect(() => { setSiteIpId(site?.ip_id ?? ""); }, [site?.id, site?.ip_id]);

  if (loading) {
    return (
      <div className="p-6 lg:p-8">
        <div className="bg-dark-800 rounded-lg border border-dark-500 p-6 animate-pulse">
          <div className="h-6 bg-dark-700 rounded w-64 mb-4" />
          <div className="h-4 bg-dark-700 rounded w-32" />
        </div>
      </div>
    );
  }

  if (error || !site) {
    return (
      <div className="p-6 lg:p-8">
        <div className="bg-danger-500/10 text-danger-400 px-4 py-3 rounded-lg border border-danger-500/20">
          {error || "Site not found"}
        </div>
        <Link to="/sites" className="text-sm text-rust-400 hover:text-rust-300 mt-4 inline-block">
          &larr; Back to sites
        </Link>
      </div>
    );
  }

  return (
    <div className="p-6 lg:p-8">
      {/* Breadcrumb */}
      <div className="mb-6">
        <Link to="/sites" className="text-sm text-dark-200 hover:text-dark-100">
          Sites
        </Link>
        <span className="text-sm text-dark-300 mx-2">/</span>
        <span className="text-sm text-dark-50 font-medium font-mono">{site.domain}</span>
      </div>

      {site.runtime === "php" && site.php_version && LEGACY_PHP_VERSIONS.has(site.php_version) && (
        <div
          role="alert"
          className="mb-6 px-4 py-3 rounded-lg text-sm bg-warn-500/10 text-warn-400 border border-warn-500/30"
        >
          PHP {site.php_version} reached end of life and gets no security updates. Plan an upgrade.
        </div>
      )}

      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <h1 className="text-sm font-medium text-dark-300 uppercase font-mono tracking-widest">{site.domain}</h1>
          <div className="flex items-center flex-wrap gap-3 mt-2">
            <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
              site.enabled === false ? "bg-warn-500/10 text-warn-400" : statusColors[site.status] || "bg-dark-700 text-dark-200"
            }`}>
              {site.enabled === false ? "disabled" : site.status}
            </span>
            <span className="text-sm text-dark-200">
              {runtimeLabels[site.runtime] || site.runtime}
            </span>
            <button disabled={checkingHealth} onClick={async () => {
              setCheckingHealth(true);
              try { const data = await api.get<{ healthy: boolean; status: number; response_time_ms: number }>(`/sites/${id}/health`); setHealth(data); }
              catch { setHealth({ healthy: false, status: 0, response_time_ms: 0 }); }
              finally { setCheckingHealth(false); }
            }} className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded text-xs font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors">
              {checkingHealth ? "Checking..." : "Health Check"}
            </button>
            {health && (
              <span className={`text-xs font-mono ${health.healthy ? "text-rust-400" : "text-danger-400"}`}>
                {health.status > 0 ? `${health.status}` : "Down"} · {health.response_time_ms}ms
              </span>
            )}
            {healthSummary && (
              <span
                title={[
                  `SSL: ${healthSummary.ssl_status.enabled ? (healthSummary.ssl_status.days_until_expiry != null ? `expires in ${healthSummary.ssl_status.days_until_expiry}d` : "enabled") : "not enabled"}`,
                  `Backup: ${healthSummary.backup_freshness.hours_since != null ? `${healthSummary.backup_freshness.hours_since}h ago` : "none on record"}`,
                  `Uptime: ${healthSummary.uptime.monitor_enabled ? (healthSummary.uptime.status || "unknown") : "not monitored"}`,
                ].join(" · ")}
                className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-mono ${
                  healthSummary.score >= 80
                    ? "bg-rust-500/10 text-rust-400"
                    : healthSummary.score >= 50
                      ? "bg-warn-500/10 text-warn-400"
                      : "bg-danger-500/10 text-danger-400"
                }`}
              >
                Health {healthSummary.score}
              </span>
            )}
            {/* ClamAV (06-clamav): hidden when it is not installed on the site's
                server. Security -> Antivirus is admin-only, hence the link gate. */}
            <SiteAntivirusStatus
              siteId={site.id}
              serverId={site.server_id}
              showSecurityLink={isAdmin}
              refreshKey={avRefreshKey}
              onStatus={setAvStatus}
            />
          </div>
        </div>
        <div>
          {confirmDelete ? (
            <div className="flex items-center gap-2">
              <span className="text-sm text-danger-400">Are you sure?</span>
              <button
                onClick={handleDelete}
                disabled={deleting}
                className="px-3 py-1.5 bg-danger-500 text-white rounded-lg text-sm hover:bg-danger-600 disabled:opacity-50"
              >
                {deleting ? "Deleting..." : "Yes, delete"}
              </button>
              <button
                onClick={() => setConfirmDelete(false)}
                className="px-3 py-1.5 bg-dark-600 text-dark-100 rounded-lg text-sm hover:bg-dark-500"
              >
                Cancel
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2">
              {/* Enable/Disable toggle */}
              <button disabled={toggling} onClick={async () => {
                setToggling(true);
                try {
                  await api.put(`/sites/${id}/toggle`, { enabled: !site?.enabled });
                  setSite(s => s ? { ...s, enabled: !s.enabled } : s);
                } catch (e) { setError(e instanceof Error ? e.message : "Toggle failed"); }
                finally { setToggling(false); }
              }} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                site?.enabled !== false
                  ? "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                  : "bg-rust-500/10 text-rust-400 hover:bg-rust-500/20"
              }`}>
                {toggling ? "..." : site?.enabled !== false ? "Disable" : "Enable"}
              </button>
              {/* Rename */}
              <button onClick={() => { setNewDomain(site?.domain || ""); setShowRename(true); setRenameMsg(""); }}
                className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 transition-colors">
                Rename
              </button>
              {/* Clone */}
              {showCloneInput ? (
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={cloneDomainValue}
                    onChange={(e) => setCloneDomainValue(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && cloneDomainValue) {
                        setShowCloneInput(false);
                        setCloning(true);
                        setCloneMsg("");
                        api.post(`/sites/${id}/clone`, { domain: cloneDomainValue })
                          .then(() => setCloneMsg(`Site cloned to ${cloneDomainValue}`))
                          .catch((err) => setCloneMsg(err instanceof Error ? err.message : "Clone failed"))
                          .finally(() => setCloning(false));
                      }
                      if (e.key === "Escape") setShowCloneInput(false);
                    }}
                    autoFocus
                    className="w-48 px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-sm font-mono text-dark-100"
                    placeholder="Clone to domain"
                  />
                  <button
                    disabled={!cloneDomainValue || cloning}
                    onClick={() => {
                      setShowCloneInput(false);
                      setCloning(true);
                      setCloneMsg("");
                      api.post(`/sites/${id}/clone`, { domain: cloneDomainValue })
                        .then(() => setCloneMsg(`Site cloned to ${cloneDomainValue}`))
                        .catch((err) => setCloneMsg(err instanceof Error ? err.message : "Clone failed"))
                        .finally(() => setCloning(false));
                    }}
                    className="px-3 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium disabled:opacity-50"
                  >
                    {cloning ? "Cloning..." : "Clone"}
                  </button>
                  <button onClick={() => setShowCloneInput(false)} className="px-3 py-2 bg-dark-600 text-dark-200 rounded-lg text-sm font-medium">Cancel</button>
                </div>
              ) : (
                /* Clone, Create Staging and Add Alias all end in
                   `domain_claim::ensure_claimable`, so all three are refusals for a
                   `client` - on the site they DO own, which is what made them read
                   as a fault rather than a rule. Hidden rather than disabled: a
                   disabled control still says "this is for you, later", and for
                   this role there is no later. */
                !isClient && (
                  <button disabled={cloning} onClick={() => { setCloneDomainValue(`clone-${site?.domain}`); setShowCloneInput(true); }}
                    className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors">
                    {cloning ? "Cloning..." : "Clone"}
                  </button>
                )
              )}
              {user?.role === "admin" && (
                showTransfer ? (
                  <div className="flex items-center gap-2">
                    {/* Picked, not typed. The endpoint answers 404 "No account
                        with that email" on a typo, so a text field could only
                        fail late - and an operator does not carry their clients'
                        addresses in their head. */}
                    <select
                      value={transferEmail}
                      onChange={(e) => setTransferEmail(e.target.value)}
                      autoFocus
                      className="w-64 px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-sm text-dark-100"
                    >
                      <option value="">Choose an account…</option>
                      {transferTargets.map((u) => (
                        <option key={u.id} value={u.email}>{u.email} ({u.role})</option>
                      ))}
                    </select>
                    <button
                      disabled={!transferEmail || transferring}
                      onClick={() => {
                        setTransferring(true);
                        setTransferMsg("");
                        api.post(`/sites/${id}/transfer`, { email: transferEmail })
                          .then(() => {
                            setShowTransfer(false);
                            setTransferMsg(
                              `Transferred to ${transferEmail}. You no longer own this site - ` +
                              `find it again under Sites → "All sites on this server".`
                            );
                          })
                          .catch((err) => setTransferMsg(err instanceof Error ? err.message : "Transfer failed"))
                          .finally(() => setTransferring(false));
                      }}
                      className="px-3 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium disabled:opacity-50"
                    >
                      {transferring ? "Transferring..." : "Transfer"}
                    </button>
                    <button onClick={() => setShowTransfer(false)} className="px-3 py-2 bg-dark-600 text-dark-200 rounded-lg text-sm font-medium">Cancel</button>
                  </div>
                ) : (
                  <button
                    onClick={() => setShowTransfer(true)}
                    title="Hand this site to another account. Ownership is exclusive - the current owner loses access."
                    className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 transition-colors"
                  >
                    Transfer
                  </button>
                )
              )}
              <button
                onClick={handleDelete}
                className="px-4 py-2 bg-danger-500/10 text-danger-400 rounded-lg text-sm font-medium hover:bg-danger-500/20 transition-colors"
              >
                Delete
              </button>
            </div>
          )}
        </div>
      </div>
      {/* Disabled banner */}
      {site.enabled === false && (
        <div className="mb-4 px-4 py-3 rounded-lg text-sm bg-warn-500/10 text-warn-500 border border-warn-500/20 flex items-center justify-between">
          <span>
            {site.bandwidth_suspended_at
              ? `This site was automatically disabled on ${formatDate(site.bandwidth_suspended_at)} for exceeding its monthly bandwidth quota (${site.bandwidth_quota_mb} MB). Visitors see a 503 maintenance page. Raise the quota below to restore it immediately, or it restores automatically next month.`
              : "This site is currently disabled. Visitors see a 503 maintenance page."}
          </span>
          <button disabled={toggling} onClick={async () => {
            setToggling(true);
            try {
              await api.put(`/sites/${id}/toggle`, { enabled: true });
              setSite(s => s ? { ...s, enabled: true, bandwidth_suspended_at: null } : s);
            } catch (e) { setError(e instanceof Error ? e.message : "Enable failed"); }
            finally { setToggling(false); }
          }} className="px-3 py-1 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-50 shrink-0 ml-3">
            {toggling ? "..." : "Enable Now"}
          </button>
        </div>
      )}

      {/* Rename modal */}
      {showRename && (
        <div className="mb-4 p-4 rounded-lg bg-dark-800 border border-dark-600">
          <h3 className="text-sm font-medium text-dark-100 mb-3">Rename Domain</h3>
          <div className="flex items-center gap-3">
            <input type="text" value={newDomain} onChange={e => setNewDomain(e.target.value)}
              placeholder="new-domain.com"
              className="flex-1 bg-dark-700 text-dark-50 border border-dark-500 rounded-lg px-3 py-2 text-sm font-mono focus:ring-1 focus:ring-rust-500 focus:border-rust-500 outline-none" />
            <button disabled={renaming || !newDomain || newDomain === site.domain} onClick={async () => {
              setRenaming(true);
              setRenameMsg("");
              try {
                await api.put(`/sites/${id}/domain`, { new_domain: newDomain });
                setRenameMsg(`Domain renamed to ${newDomain}`);
                setSite(s => s ? { ...s, domain: newDomain } : s);
                setShowRename(false);
              } catch (e) { setRenameMsg(e instanceof Error ? e.message : "Rename failed"); }
              finally { setRenaming(false); }
            }} className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50">
              {renaming ? "Renaming..." : "Rename"}
            </button>
            <button onClick={() => setShowRename(false)} className="px-4 py-2 bg-dark-600 text-dark-100 rounded-lg text-sm hover:bg-dark-500">
              Cancel
            </button>
          </div>
          {renameMsg && (
            <p className={`mt-2 text-xs ${renameMsg.includes("renamed") ? "text-rust-400" : "text-danger-400"}`}>{renameMsg}</p>
          )}
        </div>
      )}

      {cloneMsg && (
        <div className={`mb-4 px-4 py-3 rounded-lg text-sm ${
          cloneMsg.includes("cloned") ? "bg-rust-500/10 text-rust-400 border border-rust-500/20" : "bg-danger-500/10 text-danger-400 border border-danger-500/20"
        }`}>{cloneMsg}</div>
      )}
      {transferMsg && (
        <div className={`mb-4 px-4 py-3 rounded-lg text-sm ${
          transferMsg.includes("Transferred") ? "bg-rust-500/10 text-rust-400 border border-rust-500/20" : "bg-danger-500/10 text-danger-400 border border-danger-500/20"
        }`}>{transferMsg}</div>
      )}

      {/* Details */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden">
        <dl className="divide-y divide-dark-600">
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">Domain</dt>
            <dd className="text-sm text-dark-50 col-span-2 font-mono">{site.domain}</dd>
          </div>
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">Runtime</dt>
            <dd className="text-sm text-dark-50 col-span-2">
              <div className="space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <span>{runtimeLabels[site.runtime] || site.runtime}</span>
                  {/* #99: the reporter's workaround was deleting the site and
                      recreating it, because there was no control here at all.
                      Offered only between static and PHP - the proxying runtimes
                      move the document root, which is a different change. */}
                  {(site.runtime === "static" || site.runtime === "php") && !runtimeTarget && (
                    <button
                      type="button"
                      onClick={() => {
                        setRuntimeMessage("");
                        setRuntimePhpChoice(site.php_version || "8.3");
                        setRuntimeTarget(site.runtime === "static" ? "php" : "static");
                      }}
                      className="text-xs px-2 py-1 rounded-lg border border-dark-600 text-dark-100 hover:text-dark-50 hover:border-dark-500"
                    >
                      {site.runtime === "static" ? "Switch to PHP" : "Switch to static"}
                    </button>
                  )}
                  {switchingRuntime && <span className="text-xs text-dark-200">Switching...</span>}
                  {runtimeMessage && (
                    <span className={`text-xs ${runtimeMessage.startsWith("Switched") ? "text-rust-400" : "text-danger-400"}`}>
                      {runtimeMessage}
                    </span>
                  )}
                </div>

                {runtimeTarget === "php" && (
                  <div className="rounded-lg border border-dark-600 p-3 space-y-3">
                    <p className="text-xs text-dark-200">
                      The document root does not move - <span className="font-mono">public/</span> keeps
                      serving the files that are already there. Existing <span className="font-mono">.html</span>{" "}
                      files keep working; <span className="font-mono">.php</span> files start executing.
                    </p>
                    <PhpVersionPicker
                      className="max-w-xs"
                      value={runtimePhpChoice}
                      canInstall={user?.role === "admin"}
                      disabled={switchingRuntime}
                      onChange={(v, ready) => { setRuntimePhpChoice(v); setRuntimePhpReady(ready); }}
                    />
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={switchingRuntime || !runtimePhpReady}
                        title={runtimePhpReady ? undefined : `PHP ${runtimePhpChoice} is not installed on this server yet - install it above first.`}
                        onClick={async () => {
                          setSwitchingRuntime(true);
                          setRuntimeMessage("");
                          try {
                            const updated = await api.put<Site>(`/sites/${id}/runtime`, {
                              runtime: "php",
                              php_version: runtimePhpChoice,
                            });
                            setSite(updated);
                            setRuntimeTarget(null);
                            setRuntimeMessage(`Switched to PHP ${runtimePhpChoice}`);
                          } catch (err) {
                            setRuntimeMessage(err instanceof Error ? err.message : "Switch failed");
                          } finally {
                            setSwitchingRuntime(false);
                          }
                        }}
                        className="text-xs px-3 py-1.5 rounded-lg bg-rust-600 text-white hover:bg-rust-500 disabled:opacity-50"
                      >
                        Switch to PHP {runtimePhpChoice}
                      </button>
                      <button
                        type="button"
                        disabled={switchingRuntime}
                        onClick={() => { setRuntimeTarget(null); setRuntimeMessage(""); }}
                        className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 text-dark-100 hover:text-dark-50"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {runtimeTarget === "static" && (
                  <div className="rounded-lg border border-dark-600 p-3 space-y-3">
                    <p className="text-xs text-dark-200">
                      PHP stops executing on this site. Your files are not touched, and switching back
                      restores execution - but anything the PHP vhost was hiding is a static file from
                      now on, so the static vhost refuses <span className="font-mono">.php</span> source
                      and dotfiles (<span className="font-mono">.env</span>,{" "}
                      <span className="font-mono">.git/</span>) outright rather than serving them.
                      Anything else in <span className="font-mono">public/</span> - database dumps,
                      backups, <span className="font-mono">composer.json</span> - becomes publicly
                      downloadable. Move it out before switching.
                    </p>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        disabled={switchingRuntime}
                        onClick={async () => {
                          setSwitchingRuntime(true);
                          setRuntimeMessage("");
                          try {
                            const updated = await api.put<Site>(`/sites/${id}/runtime`, { runtime: "static" });
                            setSite(updated);
                            setRuntimeTarget(null);
                            setRuntimeMessage("Switched to static");
                          } catch (err) {
                            setRuntimeMessage(err instanceof Error ? err.message : "Switch failed");
                          } finally {
                            setSwitchingRuntime(false);
                          }
                        }}
                        className="text-xs px-3 py-1.5 rounded-lg bg-danger-600 text-white hover:bg-danger-500 disabled:opacity-50"
                      >
                        Switch to static
                      </button>
                      <button
                        type="button"
                        disabled={switchingRuntime}
                        onClick={() => { setRuntimeTarget(null); setRuntimeMessage(""); }}
                        className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 text-dark-100 hover:text-dark-50"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </dd>
          </div>
          {site.proxy_port && (
            <div className="px-5 py-4 grid grid-cols-3">
              <dt className="text-sm font-medium text-dark-200">Proxy Port</dt>
              <dd className="text-sm text-dark-50 col-span-2 font-mono">{site.proxy_port}</dd>
            </div>
          )}
          {site.runtime === "php" && (
            <div className="px-5 py-4 grid grid-cols-3">
              <dt className="text-sm font-medium text-dark-200">PHP Version</dt>
              <dd className="text-sm col-span-2">
                <div className="space-y-2">
                  <div className="flex items-center gap-3">
                    {/* Picking a version this server does not have used to fire
                        the switch anyway and surface the agent's refusal. The
                        picker now knows, holds the selection back, and offers the
                        install - then switches once the version really works. */}
                    <PhpVersionPicker
                      className="max-w-xs"
                      value={phpChoice || site.php_version || "8.3"}
                      canInstall={user?.role === "admin"}
                      disabled={switchingPhp}
                      onChange={async (newVersion, ready) => {
                        setPhpChoice(newVersion);
                        if (!ready || newVersion === site.php_version) return;
                        setSwitchingPhp(true);
                        setPhpMessage("");
                        setPhpWarning("");
                        try {
                          const updated = await api.put<Site & { warning?: string }>(`/sites/${id}/php`, { version: newVersion });
                          const { warning, ...rest } = updated;
                          setSite(rest);
                          setPhpMessage(`Switched to PHP ${newVersion}`);
                          if (warning) setPhpWarning(warning);
                        } catch (err) {
                          setPhpMessage(err instanceof Error ? err.message : "Switch failed");
                          // Put the control back on what the site is actually
                          // running. Leaving it on the version that just failed
                          // states the switch happened, and - because the guard
                          // above short-circuits when the selection already
                          // equals the current version - makes retrying the same
                          // version impossible without picking a third one first.
                          setPhpChoice(site.php_version || "");
                        } finally {
                          setSwitchingPhp(false);
                        }
                      }}
                    />
                    {switchingPhp && (
                      <span className="text-xs text-dark-200">Switching...</span>
                    )}
                    {phpMessage && (
                      <span className={`text-xs ${phpMessage.includes("Switched") ? "text-rust-400" : "text-danger-400"}`}>
                        {phpMessage}
                      </span>
                    )}
                  </div>
                  {phpWarning && (
                    <p className="text-xs px-3 py-2 rounded-lg bg-warn-500/10 text-warn-400 border border-warn-500/30 max-w-xl">
                      {phpWarning}
                    </p>
                  )}
                </div>
              </dd>
            </div>
          )}
          {site.runtime === "php" && site.php_preset && site.php_preset !== "generic" && (
            <div className="px-5 py-4 grid grid-cols-3">
              <dt className="text-sm font-medium text-dark-200">Framework</dt>
              <dd className="text-sm text-dark-50 col-span-2 capitalize">{site.php_preset}</dd>
            </div>
          )}
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">SSL</dt>
            <dd className="text-sm col-span-2">
              {site.ssl_enabled ? (
                <div className="space-y-1">
                  <span className="inline-flex items-center gap-1 text-rust-400">
                    <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M10 1a4.5 4.5 0 0 0-4.5 4.5V9H5a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-6a2 2 0 0 0-2-2h-.5V5.5A4.5 4.5 0 0 0 10 1Zm3 8V5.5a3 3 0 1 0-6 0V9h6Z" clipRule="evenodd" />
                    </svg>
                    {sslProvenance?.provenance === "foreign" && sslProvenance.issuer
                      ? `Enabled (${sslProvenance.issuer})`
                      : sslProvenance?.provenance === "dockpanel"
                        ? "Enabled (Let's Encrypt)"
                        : "Enabled"}
                  </span>
                  {site.ssl_expiry && (
                    <p className="text-xs text-dark-200">
                      Expires: {new Date(site.ssl_expiry).toLocaleDateString()}
                    </p>
                  )}
                  <div className="pt-2 space-y-2">
                    {([
                      {
                        key: "force_ssl" as const,
                        label: "Force HTTPS",
                        hint: "Redirect every HTTP request to HTTPS.",
                      },
                      {
                        key: "hsts" as const,
                        label: "HSTS",
                        hint: "Tell browsers to only ever use HTTPS for this domain.",
                      },
                    ]).map((opt) => {
                      const current = {
                        force_ssl: site.force_ssl ?? true,
                        hsts: site.hsts ?? true,
                      };
                      const on = current[opt.key];
                      return (
                        <div key={opt.key} className="flex items-center gap-3">
                          <button
                            type="button"
                            role="switch"
                            aria-checked={on}
                            aria-label={opt.label}
                            disabled={savingSslOpts}
                            onClick={() => saveSslOptions({ ...current, [opt.key]: !on })}
                            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-50 ${
                              on ? "bg-rust-500" : "bg-dark-600"
                            }`}
                          >
                            <span
                              className={`inline-block h-4 w-4 rounded-full bg-white transition-transform ${
                                on ? "translate-x-4" : "translate-x-0.5"
                              }`}
                            />
                          </button>
                          <div>
                            <span className="text-xs text-dark-100">{opt.label}</span>
                            <span className="text-xs text-dark-400 ml-2">{opt.hint}</span>
                          </div>
                        </div>
                      );
                    })}
                    {sslOptsMsg && <p className="text-xs text-danger-400">{sslOptsMsg}</p>}
                  </div>
                  {sslProvenance?.provenance === "foreign" && (
                    <p className="text-xs text-dark-300">
                      CyberHunter - Panel did not issue this certificate and will not renew it. Renew it
                      wherever it was issued, then install the replacement here.
                    </p>
                  )}
                  {/* ⛔ THE CONTROL THAT WAS MISSING. Three separate refusals in
                      this product tell the operator to "install a replacement
                      under the site's SSL tab" - the renew door, the security
                      scanner's declined-renewal alert and the DNS-01 renewal
                      plan. Every SSL control, the upload form included, used to
                      live in the `else` branch below, so once SSL was on there
                      was nothing on this page to act on. Revoke is admin-only
                      and the certificate list's controls are admin-only too, so
                      a site's own non-admin owner holding a commercial
                      certificate had NO reachable path at all: the panel
                      correctly declined to renew, then named a control that did
                      not exist. The form itself is shared with the `else`
                      branch - see below the ternary - so this is a disclosure,
                      not a second copy. */}
                  {site.status === "active" && (
                    <div className="pt-1">
                      <button
                        type="button"
                        onClick={() => setShowSslUpload(!showSslUpload)}
                        aria-expanded={showSslUpload}
                        className="text-xs text-dark-300 hover:text-dark-100 underline decoration-dotted underline-offset-2 transition-colors"
                      >
                        Replace certificate
                      </button>
                      <p className="mt-1 text-xs text-dark-400">
                        Paste a certificate and private key you already hold. You renew it yourself.
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div>
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className="text-dark-300">Not configured</span>
                    {site.status === "active" && (
                      <>
                        <button
                          onClick={() => handleProvisionSSL()}
                          disabled={provisioning || prereqBlocks(dnsPrereq)}
                          title={prereqBlocks(dnsPrereq) ? dnsPrereq?.title : undefined}
                          className="px-3 py-1 bg-rust-500 text-white rounded-md text-xs font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
                        >
                          {provisioning ? "Securing..." : "Secure this site"}
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            const next = !showSslOptions;
                            setShowSslOptions(next);
                            // Collapsing the section must also close the upload
                            // form it opened, or the textareas stay on screen
                            // with nothing visible explaining them.
                            if (!next) setShowSslUpload(false);
                          }}
                          aria-expanded={showSslOptions}
                          className="text-xs text-dark-300 hover:text-dark-100 underline decoration-dotted underline-offset-2 transition-colors"
                        >
                          Other options
                        </button>
                      </>
                    )}
                  </div>
                  {site.status === "active" && !showSslOptions && (
                    <p className="mt-1.5 text-xs text-dark-400">
                      Issues a free Let&apos;s Encrypt certificate and renews it automatically.
                    </p>
                  )}
                  {site.status === "active" && showSslOptions && (
                    <div className="mt-3 space-y-2 border-l-2 border-dark-600 pl-3">
                      <div>
                        <button
                          onClick={() => handleProvisionDns01(false)}
                          disabled={dns01Loading || provisioning}
                          className="px-3 py-1 bg-accent-500/20 text-accent-400 rounded-md text-xs font-medium hover:bg-accent-500/30 disabled:opacity-50 transition-colors"
                        >
                          {dns01Loading ? "Provisioning..." : "Verify via Cloudflare DNS"}
                        </button>
                        <p className="mt-1 text-xs text-dark-400">
                          For when port 80 cannot be reached from the internet. Needs a Cloudflare
                          API token (DNS-01 challenge).
                        </p>
                      </div>
                      <div>
                        <button
                          onClick={() => handleProvisionDns01(true)}
                          disabled={dns01Loading || provisioning}
                          className="px-3 py-1 bg-accent-500/10 text-accent-300 rounded-md text-xs font-medium hover:bg-accent-500/20 disabled:opacity-50 transition-colors"
                        >
                          {dns01Loading ? "..." : "Wildcard certificate"}
                        </button>
                        <p className="mt-1 text-xs text-dark-400">
                          Covers every subdomain (<span className="font-mono">*.{site.domain}</span>).
                          Also via Cloudflare DNS.
                        </p>
                      </div>
                      <div>
                        <button
                          onClick={() => setShowSslUpload(!showSslUpload)}
                          className="px-3 py-1 bg-dark-700 text-dark-100 rounded-md text-xs font-medium hover:bg-dark-600 transition-colors"
                        >
                          Upload my own certificate
                        </button>
                        <p className="mt-1 text-xs text-dark-400">
                          Paste a certificate and private key you already hold. You renew it yourself.
                        </p>
                      </div>
                    </div>
                  )}
                  {/* The prerequisite itself: what is wrong, what we expected,
                      what we saw, and the exact record to create. */}
                  {site.status === "active" && (
                    <PrereqCallout
                      prereq={dnsPrereq}
                      onRecheck={recheckDns}
                      checking={dnsChecking}
                      className="mt-3"
                    />
                  )}
                </div>
              )}

              {/* ⛔ SHARED BY BOTH BRANCHES, WHICH IS THE WHOLE POINT - hoisted
                  out of the `else` above rather than copied into the `true`
                  side. Two instances would mean two `showSslUpload` reads of one
                  state and a second success handler to drift, and a duplicated
                  form is exactly what a later reader deletes "as dead code" from
                  whichever branch they happened to be looking at. Every piece of
                  state it touches was already declared at component scope, so
                  the move needs no lifting and no props. */}
              {showSslUpload && (
                <div className="mt-3 space-y-3">
                  <textarea value={sslCert} onChange={e => setSslCert(e.target.value)}
                    placeholder={"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"}
                    rows={4} className="w-full px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-xs font-mono text-dark-100 focus:ring-2 focus:ring-accent-500 outline-none" />
                  <textarea value={sslKey} onChange={e => setSslKey(e.target.value)}
                    placeholder={"-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"}
                    rows={4} className="w-full px-3 py-2 bg-dark-900 border border-dark-500 rounded-lg text-xs font-mono text-dark-100 focus:ring-2 focus:ring-accent-500 outline-none" />
                  <button disabled={uploadingSsl || !sslCert || !sslKey} onClick={async () => {
                    setUploadingSsl(true);
                    setSslMessage("");
                    try {
                      await api.post(`/sites/${id}/ssl/upload`, { certificate: sslCert, private_key: sslKey });
                      setSslMessage("Custom SSL certificate installed successfully!");
                      setSslMessageIsError(false);
                      setSslCert(""); setSslKey(""); setShowSslUpload(false);
                      const updated = await api.get<Site>(`/sites/${id}`);
                      setSite(updated);
                      // The badge names the issuer, so replacing the certificate
                      // must re-ask who issued it. `ssl_enabled` was already true
                      // on a replace, so the effect keyed on it does NOT re-run.
                      loadSslProvenance();
                    } catch (e) {
                      setSslMessage(e instanceof Error ? e.message : "Upload failed");
                      setSslMessageIsError(true);
                    }
                    finally { setUploadingSsl(false); }
                  }} className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50">
                    {uploadingSsl ? "Installing..." : "Install Certificate"}
                  </button>
                </div>
              )}

              {/* The refusal that used to be a dead end. The agent's
                  provision writer declines by default over a certificate
                  this product did not issue - correct, since a purchased
                  wildcard or an Origin CA cert is a paid asset nobody asked
                  to have replaced - but until this control existed the only
                  way past it was `dockpanel ssl provision --force` on the
                  CLI, with the panel's own button offering no path forward
                  at all. This asks the SAME confirmation the CLI's `--force`
                  requires: read what would be lost, then say so explicitly. */}
              {foreignCertRefusal && (
                <div
                  role="alert"
                  className="mt-3 px-3 py-2 rounded text-xs bg-warn-500/10 text-warn-400 border border-warn-500/20 space-y-2"
                >
                  <p>{foreignCertRefusal.message}</p>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      disabled={forcingSsl}
                      onClick={foreignCertRefusal.retry}
                      className="px-3 py-1 bg-danger-500/20 text-danger-400 rounded-md text-xs font-medium hover:bg-danger-500/30 disabled:opacity-50 transition-colors"
                    >
                      {forcingSsl ? "Replacing..." : "Replace it anyway"}
                    </button>
                    <button
                      type="button"
                      disabled={forcingSsl}
                      onClick={() => setForeignCertRefusal(null)}
                      className="text-xs text-dark-300 hover:text-dark-100 underline decoration-dotted underline-offset-2 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}

              {/* The result of the button the user just pressed, BESIDE that
                  button. This used to render ~1400 lines further down the
                  page, at the very bottom of the document - so a perfectly
                  good 412 explaining the DNS problem was on screen but
                  nowhere the user would ever look, and clicking "Let's
                  Encrypt" appeared to do nothing at all (s252 F1). */}
              {sslMessage && (
                <div
                  role="alert"
                  className={`mt-3 px-3 py-2 rounded text-xs ${
                    sslMessageIsError
                      ? "bg-danger-500/10 text-danger-400 border border-danger-500/20"
                      : "bg-rust-500/10 text-rust-400 border border-rust-500/20"
                  }`}
                >
                  {sslMessage}
                </div>
              )}
            </dd>
          </div>
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">Status</dt>
            <dd className="text-sm col-span-2">
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColors[site.status] || "bg-dark-700 text-dark-200"}`}>
                {site.status}
              </span>
            </dd>
          </div>
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">Created</dt>
            <dd className="text-sm text-dark-50 col-span-2">
              {formatDate(site.created_at)}
            </dd>
          </div>
          <div className="px-5 py-4 grid grid-cols-3">
            <dt className="text-sm font-medium text-dark-200">Last Updated</dt>
            <dd className="text-sm text-dark-50 col-span-2">
              {formatDate(site.updated_at)}
            </dd>
          </div>
        </dl>
      </div>

      {/* Antivirus detections of this site (owner routes only). */}
      <SiteAntivirusDetections siteId={site.id} status={avStatus} onChanged={bumpAvStatus} />

      {/* Quick actions */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mt-6">
        <Link
          to={`/sites/${id}/files`}
          className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-warn-500/10 rounded-lg text-warn-400 group-hover:bg-warn-500/20 transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12.75V12A2.25 2.25 0 0 1 4.5 9.75h15A2.25 2.25 0 0 1 21.75 12v.75m-8.69-6.44-2.12-2.12a1.5 1.5 0 0 0-1.061-.44H4.5A2.25 2.25 0 0 0 2.25 6v12a2.25 2.25 0 0 0 2.25 2.25h15A2.25 2.25 0 0 0 21.75 18V9a2.25 2.25 0 0 0-2.25-2.25h-5.379a1.5 1.5 0 0 1-1.06-.44Z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-dark-50">File Manager</p>
              <p className="text-xs text-dark-200">Browse & edit files</p>
            </div>
          </div>
        </Link>
        <Link
          to={`/terminal?site=${id}`}
          className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-dark-500/10 rounded-lg text-dark-400 group-hover:bg-dark-500/20 transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="m6.75 7.5 3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0 0 21 18V6a2.25 2.25 0 0 0-2.25-2.25H5.25A2.25 2.25 0 0 0 3 6v12a2.25 2.25 0 0 0 2.25 2.25Z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-dark-50">Terminal</p>
              <p className="text-xs text-dark-200">SSH-like access</p>
            </div>
          </div>
        </Link>
        <Link
          to={`/sites/${id}/backups`}
          className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-rust-500/10 rounded-lg text-rust-500 group-hover:bg-accent-500/20 transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M20.25 7.5l-.625 10.632a2.25 2.25 0 0 1-2.247 2.118H6.622a2.25 2.25 0 0 1-2.247-2.118L3.75 7.5m8.25 3v6.75m0 0-3-3m3 3 3-3M3.375 7.5h17.25c.621 0 1.125-.504 1.125-1.125v-1.5c0-.621-.504-1.125-1.125-1.125H3.375c-.621 0-1.125.504-1.125 1.125v1.5c0 .621.504 1.125 1.125 1.125Z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-dark-50">Backups</p>
              <p className="text-xs text-dark-200">Create & restore</p>
            </div>
          </div>
        </Link>
        <Link
          to={`/sites/${id}/crons`}
          className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-accent-600/10 rounded-lg text-accent-400 group-hover:bg-accent-600/20 transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-dark-50">Cron Jobs</p>
              <p className="text-xs text-dark-200">Scheduled tasks</p>
            </div>
          </div>
        </Link>
        <Link
          to={`/sites/${id}/deploy`}
          className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
        >
          <div className="flex items-center gap-3">
            <div className="p-2 bg-rust-500/10 rounded-lg text-rust-400 group-hover:bg-rust-500/20 transition-colors">
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M17.25 6.75 22.5 12l-5.25 5.25m-10.5 0L1.5 12l5.25-5.25m7.5-3-4.5 16.5" />
              </svg>
            </div>
            <div>
              <p className="text-sm font-medium text-dark-50">Git Deploy</p>
              <p className="text-xs text-dark-200">Push to deploy</p>
            </div>
          </div>
        </Link>
        {site.php_preset === "wordpress" && (
          <Link
            to={`/sites/${id}/wordpress`}
            className="bg-dark-800 rounded-lg border border-dark-500 p-5 hover:border-accent-400 hover:shadow-sm transition-all group"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 bg-accent-500/10 rounded-lg text-accent-400 group-hover:bg-accent-500/20 transition-colors">
                <svg className="w-5 h-5" viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 2C6.486 2 2 6.486 2 12s4.486 10 10 10 10-4.486 10-10S17.514 2 12 2zm0 2c1.67 0 3.214.52 4.488 1.401L5.401 16.488A7.957 7.957 0 0 1 4 12c0-4.411 3.589-8 8-8zm0 16c-1.67 0-3.214-.52-4.488-1.401L18.599 7.512A7.957 7.957 0 0 1 20 12c0 4.411-3.589 8-8 8z" />
                </svg>
              </div>
              <div>
                <p className="text-sm font-medium text-dark-50">WordPress</p>
                <p className="text-xs text-dark-200">Manage WP</p>
              </div>
            </div>
          </Link>
        )}
      </div>

      {/* IP Address - admin only (server IPs are a host-level setting) */}
      {isAdmin && site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">IP Address</h2>
            <span className="text-xs font-mono text-dark-100">
              {(site.ip_id && serverIps.find((ip) => ip.id === site.ip_id)?.ip) || site.bind_ip || "Primary IP"}
            </span>
          </div>
          <div className="p-5 space-y-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1 min-w-[16rem]">
                <label htmlFor="site-ip-select" className="block text-xs font-medium text-dark-200 mb-1">Listen on</label>
                <select
                  id="site-ip-select"
                  value={siteIpId}
                  onChange={(e) => { setSiteIpId(e.target.value); setIpMessage(null); }}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm bg-dark-800 font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                >
                  <option value="">Primary IP</option>
                  {serverIps.filter((ip) => !ip.is_primary || ip.id === site.ip_id).map((ip) => (
                    <option key={ip.id} value={ip.id}>{serverIpOptionLabel(ip)}</option>
                  ))}
                  {/* The site's IP may not be in this server's list (other
                      server selected, list failed): keep it selectable so a
                      Save never silently moves the site to the primary IP. */}
                  {site.ip_id && !serverIps.some((ip) => ip.id === site.ip_id) && (
                    <option value={site.ip_id}>{site.bind_ip || site.ip_id} (current)</option>
                  )}
                </select>
              </div>
              <button
                disabled={savingIp || siteIpId === (site.ip_id ?? "")}
                onClick={async () => {
                  setSavingIp(true);
                  setIpMessage(null);
                  try {
                    const updated = await api.put<Site & { mail_warning?: string | null }>(`/sites/${id}/ip`, { ip_id: siteIpId || null });
                    const { mail_warning, ...siteOnly } = updated;
                    setSite(siteOnly);
                    const base = `Site now listens on ${updated.bind_ip || "the primary IP"}`;
                    setIpMessage(mail_warning
                      ? { text: `${base}. Mail warning: ${mail_warning}`, error: true }
                      : { text: base, error: false });
                  } catch (err) {
                    setIpMessage({ text: err instanceof Error ? err.message : "Save failed", error: true });
                  } finally {
                    setSavingIp(false);
                  }
                }}
                className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
              >
                {savingIp ? "Saving..." : "Save"}
              </button>
            </div>
            {ipMessage && (
              <p className={`text-xs ${ipMessage.error ? "text-danger-400" : "text-rust-400"}`}>{ipMessage.text}</p>
            )}
            {serverIpsLoaded && serverIps.filter((ip) => !ip.is_primary).length === 0 && (
              <p className="text-xs text-dark-400">
                No additional IP declared on this server. Add one in <Link to="/ips" className="text-accent-400 hover:text-accent-300">IP Addresses</Link>.
              </p>
            )}
            <p className="text-xs text-dark-400">
              DNS A records are updated automatically only for zones managed by the panel. If the DNS of {site.domain} is hosted elsewhere, update its A record yourself after changing the IP. A mail domain with the same name in automatic mode follows this IP for sending.
            </p>
          </div>
        </div>
      )}

      {/* Resource Limits */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Resource Limits</h2>
          </div>
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div>
                <label className="block text-xs font-medium text-dark-200 mb-1">Rate Limit (req/s per IP)</label>
                <input
                  type="number"
                  value={rateLimit}
                  onChange={(e) => setRateLimit(e.target.value)}
                  placeholder="Unlimited"
                  min="1"
                  max="10000"
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-dark-200 mb-1">Max Upload (MB)</label>
                <input
                  type="number"
                  value={maxUpload}
                  onChange={(e) => setMaxUpload(e.target.value)}
                  min="1"
                  max="10240"
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-dark-200 mb-1">Bandwidth Quota (MB/mo)</label>
                <input
                  type="number"
                  value={bandwidthQuota}
                  onChange={(e) => setBandwidthQuota(e.target.value)}
                  placeholder="Unlimited"
                  min="1"
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                />
              </div>
              {site.runtime === "php" && (
                <>
                  <div>
                    <label className="block text-xs font-medium text-dark-200 mb-1">PHP Memory (MB)</label>
                    <input
                      type="number"
                      value={phpMemory}
                      onChange={(e) => setPhpMemory(e.target.value)}
                      min="32"
                      max="4096"
                      className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-dark-200 mb-1">PHP Workers</label>
                    <input
                      type="number"
                      value={phpWorkers}
                      onChange={(e) => setPhpWorkers(e.target.value)}
                      min="1"
                      max="100"
                      className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                    />
                  </div>
                </>
              )}
            </div>
            {/* Custom Nginx Directives */}
            <div>
              <label className="block text-xs font-medium text-dark-200 mb-1">
                Custom Nginx Directives <span className="text-dark-300 font-normal">(injected into server block)</span>
              </label>
              <textarea
                value={customNginx}
                onChange={(e) => setCustomNginx(e.target.value)}
                rows={4}
                placeholder={"# Example:\n# add_header X-Custom-Header \"value\";\n# location /api { proxy_pass http://localhost:3000; }"}
                spellCheck={false}
                className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none resize-y"
              />
              <p className="text-[10px] text-dark-300 mt-1">
                Config is validated before applying. Invalid directives will be rejected.
              </p>
            </div>

            {bandwidthUsage && (
              <div>
                <div className="flex items-center justify-between text-xs text-dark-300 mb-1">
                  <span>
                    Bandwidth this month ({bandwidthUsage.year_month}):{" "}
                    {(bandwidthUsage.used_bytes_this_month / 1024 / 1024).toFixed(1)} MB
                    {site.bandwidth_quota_mb ? ` of ${site.bandwidth_quota_mb} MB` : " (unlimited)"}
                  </span>
                </div>
                {site.bandwidth_quota_mb != null && (
                  <div className="w-full h-1.5 bg-dark-700 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${
                        bandwidthUsage.used_bytes_this_month / 1024 / 1024 > site.bandwidth_quota_mb
                          ? "bg-danger-500"
                          : bandwidthUsage.used_bytes_this_month / 1024 / 1024 > site.bandwidth_quota_mb * 0.8
                          ? "bg-warn-500"
                          : "bg-rust-500"
                      }`}
                      style={{
                        width: `${Math.min(
                          100,
                          (bandwidthUsage.used_bytes_this_month / 1024 / 1024 / site.bandwidth_quota_mb) * 100
                        )}%`,
                      }}
                    />
                  </div>
                )}
              </div>
            )}

            <div className="flex items-center justify-between">
              <p className="text-xs text-dark-300">
                {rateLimit ? `${rateLimit} req/s per IP` : "No rate limit"} · {maxUpload} MB uploads
                {site.runtime === "php" ? ` · ${phpMemory} MB memory · ${phpWorkers} workers` : ""}
                {bandwidthQuota ? ` · ${bandwidthQuota} MB/mo bandwidth` : " · Unlimited bandwidth"}
              </p>
              <div className="flex items-center gap-3">
                {limitsMessage && (
                  <span className={`text-xs ${limitsMessage.includes("saved") ? "text-rust-400" : "text-danger-400"}`}>
                    {limitsMessage}
                  </span>
                )}
                <button
                  disabled={savingLimits}
                  onClick={async () => {
                    setSavingLimits(true);
                    setLimitsMessage("");
                    try {
                      const updated = await api.put<Site>(`/sites/${id}/limits`, {
                        rate_limit: rateLimit ? parseInt(rateLimit) : null,
                        max_upload_mb: parseInt(maxUpload) || 64,
                        php_memory_mb: parseInt(phpMemory) || 256,
                        php_max_workers: parseInt(phpWorkers) || 5,
                        custom_nginx: customNginx || null,
                        bandwidth_quota_mb: bandwidthQuota ? parseInt(bandwidthQuota) : null,
                      });
                      setSite(updated);
                      setLimitsMessage(
                        updated.enabled && site.enabled === false
                          ? "Limits saved - site re-enabled"
                          : "Limits saved"
                      );
                    } catch (err) {
                      setLimitsMessage(err instanceof Error ? err.message : "Save failed");
                    } finally {
                      setSavingLimits(false);
                    }
                  }}
                  className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
                >
                  {savingLimits ? "Saving..." : "Apply Limits"}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* PHP Settings - per-site php.ini values, isolation and pool. A save can
          change php_memory_mb / php_max_workers, which Resource Limits above
          also sends: re-read the site and resync ONLY those two inputs, so the
          next "Apply Limits" cannot revert them (and unsaved limit edits stay). */}
      {site.runtime === "php" && site.status === "active" && id && (
        <PhpSettingsCard
          siteId={id}
          refreshKey={`${site.php_version}|${site.php_memory_mb}|${site.php_max_workers}|${site.max_upload_mb}`}
          onSaved={() => {
            api
              .get<Site>(`/sites/${id}`)
              .then((s) => {
                setSite(s);
                setPhpMemory(String(s.php_memory_mb));
                setPhpWorkers(String(s.php_max_workers));
              })
              .catch(() => {});
          }}
        />
      )}

      {/* Web server - PHP sites only */}
      {site.runtime === "php" && (() => {
        const mode = site.web_server === "apache" ? "apache" : "nginx";
        const target = mode === "apache" ? "nginx" : "apache";
        // Only the nginx -> Apache direction is blocked: a site already in
        // Apache mode can always go back to nginx only.
        const apacheUnsupported = apacheStatus.supported === false;
        const showApacheUnsupported =
          webServerTarget === "apache" && (apacheUnsupported || webServerApacheUnsupported);
        const showApacheCallout =
          webServerTarget === "apache" &&
          !showApacheUnsupported &&
          (webServerApacheMissing || apacheStatus.installed === false);
        return (
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
            <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
              <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Web server</h2>
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                mode === "apache" ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
              }`}>
                {mode === "apache" ? "nginx + Apache (.htaccess)" : "nginx only"}
              </span>
            </div>
            <div className="p-5 space-y-4">
              {mode === "apache" ? (
                <p className="text-sm text-dark-200">
                  nginx serves static files and passes PHP requests to Apache. .htaccess files are read.{" "}
                  <span className="font-mono">php_value</span> / <span className="font-mono">php_flag</span> in
                  .htaccess do not work with PHP-FPM: use PHP settings or <span className="font-mono">.user.ini</span>.
                </p>
              ) : (
                <p className="text-sm text-dark-200">
                  nginx serves the site on its own. .htaccess files are ignored: rewrite rules have to be
                  written as nginx configuration.
                </p>
              )}

              {webServerTarget ? (
                <div className="rounded-lg border border-warn-500/30 bg-warn-500/5 p-3 space-y-3">
                  <p className="text-xs text-dark-200">
                    {webServerTarget === "apache"
                      ? "Switch this site to nginx + Apache? Its vhost is rebuilt and its .htaccess files start being read, including rules that were ignored until now. The FastCGI cache is not used in this mode (its setting is kept)."
                      : "Switch this site to nginx only? Its vhost is rebuilt and its .htaccess files stop being read: the rewrite rules and redirects they contain no longer apply."}
                  </p>
                  {showApacheUnsupported && (
                    <ApacheUnsupportedNotice
                      disabled={webServerSwitching}
                      onUseNginx={() => {
                        setWebServerTarget(null);
                        setWebServerApacheMissing(false);
                        setWebServerApacheUnsupported(false);
                      }}
                    />
                  )}
                  {showApacheCallout && (
                    <ApacheInstallCallout
                      canInstall={user?.role === "admin"}
                      recheck={apacheStatus.refresh}
                      disabled={webServerSwitching}
                      installLabel={webServerApacheMissing ? "Install Apache and switch" : "Install Apache"}
                      onInstalled={() => {
                        const retry = webServerApacheMissing;
                        setWebServerApacheMissing(false);
                        if (retry) switchWebServer("apache");
                      }}
                      onUseNginx={() => { setWebServerTarget(null); setWebServerApacheMissing(false); }}
                    />
                  )}
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      disabled={webServerSwitching || showApacheUnsupported}
                      onClick={() => switchWebServer(webServerTarget)}
                      className="text-xs px-3 py-1.5 rounded-lg bg-rust-600 text-white hover:bg-rust-500 disabled:opacity-50"
                    >
                      {webServerSwitching
                        ? "Switching..."
                        : webServerTarget === "apache" ? "Switch to nginx + Apache" : "Switch to nginx only"}
                    </button>
                    <button
                      type="button"
                      disabled={webServerSwitching}
                      onClick={() => {
                        setWebServerTarget(null);
                        setWebServerApacheMissing(false);
                        setWebServerApacheUnsupported(false);
                        setWebServerMsg("");
                      }}
                      className="text-xs px-3 py-1.5 rounded-lg border border-dark-600 text-dark-100 hover:text-dark-50"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-3 flex-wrap">
                  <button
                    type="button"
                    disabled={target === "apache" && apacheUnsupported}
                    onClick={() => {
                      setWebServerMsg("");
                      setWebServerApacheMissing(false);
                      setWebServerApacheUnsupported(false);
                      setWebServerTarget(target);
                    }}
                    className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 transition-colors disabled:opacity-50 disabled:hover:bg-dark-700"
                  >
                    {target === "apache" ? "Switch to nginx + Apache" : "Switch to nginx only"}
                  </button>
                  {target === "apache" && apacheUnsupported && (
                    <span className="text-xs text-dark-300">{APACHE_UNSUPPORTED_MESSAGE}</span>
                  )}
                </div>
              )}
              {webServerMsg && (
                <p className={`text-xs ${webServerMsg.startsWith("Switched") ? "text-rust-400" : "text-danger-400"}`}>
                  {webServerMsg}
                </p>
              )}
            </div>
          </div>
        );
      })()}

      {/* FastCGI Cache - PHP sites only */}
      {site.runtime === "php" && site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">FastCGI Cache</h2>
            <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
              site.web_server === "apache" ? "bg-dark-700 text-dark-300" :
              site.fastcgi_cache ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
            }`}>
              {site.web_server === "apache" ? "Not used" : site.fastcgi_cache ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-dark-200">
              Caches PHP responses at the Nginx level. Dramatically improves page load times for WordPress, Laravel, and other PHP applications. Logged-in users and POST requests bypass the cache automatically.
            </p>
            {site.web_server === "apache" && (
              <p className="text-sm text-warn-400">
                Not used in nginx + Apache mode: PHP requests go to Apache, not through the FastCGI cache.
                The setting ({site.fastcgi_cache ? "enabled" : "disabled"}) is kept and applies again if the site is switched to nginx only.
              </p>
            )}
            <div className={`flex items-center gap-3 ${site.web_server === "apache" ? "hidden" : ""}`}>
              <button
                disabled={cacheToggling}
                onClick={async () => {
                  setCacheToggling(true);
                  setCacheMsg("");
                  try {
                    await api.put(`/sites/${id}/fastcgi-cache`, { enabled: !site.fastcgi_cache });
                    setSite(s => s ? { ...s, fastcgi_cache: !s.fastcgi_cache } : s);
                    setCacheMsg(site.fastcgi_cache ? "Cache disabled" : "Cache enabled");
                  } catch (e) {
                    setCacheMsg(e instanceof Error ? e.message : "Toggle failed");
                  } finally {
                    setCacheToggling(false);
                  }
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                  site.fastcgi_cache
                    ? "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                    : "bg-rust-500 text-white hover:bg-rust-600"
                }`}
              >
                {cacheToggling ? "..." : site.fastcgi_cache ? "Disable Cache" : "Enable Cache"}
              </button>
              {site.fastcgi_cache && (
                <button
                  disabled={cachePurging}
                  onClick={async () => {
                    setCachePurging(true);
                    setCacheMsg("");
                    try {
                      await api.post(`/sites/${id}/fastcgi-cache/purge`);
                      setCacheMsg("Cache purged");
                    } catch (e) {
                      setCacheMsg(e instanceof Error ? e.message : "Purge failed");
                    } finally {
                      setCachePurging(false);
                    }
                  }}
                  className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                >
                  {cachePurging ? "Purging..." : "Purge Cache"}
                </button>
              )}
              {cacheMsg && (
                <span className={`text-xs ${cacheMsg.includes("failed") || cacheMsg.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {cacheMsg}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Redis Object Cache - PHP sites only */}
      {site.runtime === "php" && site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Redis Object Cache</h2>
            <div className="flex items-center gap-2">
              {site.redis_cache && (
                <span className="text-[10px] font-mono text-dark-400">DB {site.redis_db}</span>
              )}
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                site.redis_cache ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
              }`}>
                {site.redis_cache ? "Enabled" : "Disabled"}
              </span>
            </div>
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-dark-200">
              Caches database queries and PHP objects in Redis for dramatically faster page loads. Essential for WordPress + WooCommerce. Each site uses an isolated Redis database.
            </p>
            <div className="flex items-center gap-3">
              <button
                disabled={redisToggling}
                onClick={async () => {
                  setRedisToggling(true);
                  setRedisMsg("");
                  try {
                    const result = await api.put<{ redis_cache: boolean; redis_db?: number }>(`/sites/${id}/redis-cache`, { enabled: !site.redis_cache });
                    setSite(s => s ? { ...s, redis_cache: result.redis_cache, redis_db: result.redis_db ?? s.redis_db } : s);
                    setRedisMsg(site.redis_cache ? "Redis cache disabled" : "Redis cache enabled");
                  } catch (e) {
                    setRedisMsg(e instanceof Error ? e.message : "Toggle failed");
                  } finally {
                    setRedisToggling(false);
                  }
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                  site.redis_cache
                    ? "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                    : "bg-rust-500 text-white hover:bg-rust-600"
                }`}
              >
                {redisToggling ? "..." : site.redis_cache ? "Disable Redis" : "Enable Redis"}
              </button>
              {site.redis_cache && (
                <button
                  disabled={redisPurging}
                  onClick={async () => {
                    setRedisPurging(true);
                    setRedisMsg("");
                    try {
                      await api.post(`/sites/${id}/redis-cache/purge`);
                      setRedisMsg("Redis cache flushed");
                    } catch (e) {
                      setRedisMsg(e instanceof Error ? e.message : "Flush failed");
                    } finally {
                      setRedisPurging(false);
                    }
                  }}
                  className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                >
                  {redisPurging ? "Flushing..." : "Flush Cache"}
                </button>
              )}
              {redisMsg && (
                <span className={`text-xs ${redisMsg.includes("failed") || redisMsg.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {redisMsg}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* SFTP Access */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">SFTP Access</h2>
            <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
              site.sftp_enabled ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
            }`}>
              {site.sftp_enabled ? "Enabled" : "Disabled"}
            </span>
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-dark-200">
              Gives this site its own Linux account, chrooted to its own files - nothing outside this
              site is ever reachable over the connection. Enabling it re-owns the site's existing
              content directory; this only happens once, when you click Enable.
            </p>
            {site.sftp_enabled && (site.sftp_username || site.sftp_uid != null) && (
              <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                <div>
                  <div className="text-dark-400 uppercase tracking-wide mb-1">Username</div>
                  <div className="text-dark-100">{site.sftp_username || `sftp${site.sftp_uid}`}</div>
                </div>
                <div>
                  <div className="text-dark-400 uppercase tracking-wide mb-1">Host / Port</div>
                  <div className="text-dark-100">{site.domain} / 22</div>
                </div>
              </div>
            )}
            {!site.sftp_enabled && (
              <div className="max-w-xs">
                <label htmlFor="sftp-username" className="block text-xs font-medium text-dark-200 mb-1">
                  Username (optional)
                </label>
                <input
                  id="sftp-username"
                  type="text"
                  value={sftpUsername}
                  onChange={(e) => setSftpUsername(e.target.value)}
                  placeholder="Default: sftp<uid>, e.g. sftp10001"
                  autoComplete="off"
                  spellCheck={false}
                  className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                />
                {sftpUsername.trim() && !SFTP_USERNAME_RE.test(sftpUsername.trim()) ? (
                  <p className="text-xs text-danger-400 mt-1">
                    Lowercase letters, digits, _ . - only, starting with a letter or _, 32 characters max.
                  </p>
                ) : (
                  <p className="text-xs text-dark-400 mt-1">Leave empty to use the default account name.</p>
                )}
              </div>
            )}
            <div className="flex items-center gap-3">
              <button
                disabled={
                  sftpToggling ||
                  (!site.sftp_enabled && !!sftpUsername.trim() && !SFTP_USERNAME_RE.test(sftpUsername.trim()))
                }
                onClick={async () => {
                  setSftpToggling(true);
                  setSftpMsg("");
                  setSftpWarning("");
                  setSftpPassword(null);
                  try {
                    const path = site.sftp_enabled ? "disable" : "enable";
                    const wanted = sftpUsername.trim();
                    const body = !site.sftp_enabled && wanted ? { username: wanted } : undefined;
                    const result = await api.post<{ sftp_enabled: boolean; warning?: string }>(
                      `/sites/${id}/sftp/${path}`,
                      body,
                    );
                    if (result.warning) setSftpWarning(result.warning);
                    if (result.sftp_enabled) setSftpUsername("");
                    // sftp_uid isn't in this response - the toggle endpoints only
                    // confirm the new state; re-fetching the site is what picks up
                    // the allocated uid after an enable.
                    setSite(s => s ? { ...s, sftp_enabled: result.sftp_enabled } : s);
                    if (result.sftp_enabled) {
                      const fresh = await api.get<Site>(`/sites/${id}`);
                      setSite(fresh);
                    }
                    setSftpMsg(site.sftp_enabled ? "SFTP disabled" : "SFTP enabled");
                  } catch (e) {
                    if (e instanceof ApiError && e.code === "username_taken") {
                      setSftpMsg("Failed: this username is already taken on the server");
                    } else {
                      setSftpMsg(e instanceof Error ? e.message : "Toggle failed");
                    }
                  } finally {
                    setSftpToggling(false);
                  }
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                  site.sftp_enabled
                    ? "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                    : "bg-rust-500 text-white hover:bg-rust-600"
                }`}
              >
                {sftpToggling ? "..." : site.sftp_enabled ? "Disable SFTP" : "Enable SFTP"}
              </button>
              {site.sftp_enabled && (
                <button
                  disabled={sftpResetting}
                  onClick={async () => {
                    setSftpResetting(true);
                    setSftpMsg("");
                    try {
                      const result = await api.post<{ password: string }>(`/sites/${id}/sftp/reset-password`);
                      setSftpPassword(result.password);
                    } catch (e) {
                      setSftpMsg(e instanceof Error ? e.message : "Reset failed");
                    } finally {
                      setSftpResetting(false);
                    }
                  }}
                  className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                >
                  {sftpResetting ? "Resetting..." : "Reset Password"}
                </button>
              )}
              {sftpMsg && (
                <span className={`text-xs ${sftpMsg.includes("failed") || sftpMsg.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {sftpMsg}
                </span>
              )}
            </div>
            {sftpWarning && (
              <p className="text-xs px-3 py-2 rounded-lg bg-warn-500/10 text-warn-400 border border-warn-500/30">
                {sftpWarning}
              </p>
            )}
            {sftpPassword && (
              <div className="bg-dark-900 rounded-lg border border-accent-500/30 p-4">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="text-xs font-medium text-accent-400 uppercase font-mono tracking-widest">
                    Password Reset Successful
                  </h3>
                  <button
                    onClick={() => setSftpPassword(null)}
                    className="text-dark-400 hover:text-dark-200 text-sm"
                    aria-label="Dismiss"
                  >
                    &times;
                  </button>
                </div>
                <p className="text-xs text-dark-300 mb-2">Save this password now - it will not be shown again after you leave this page.</p>
                <div className="flex items-center gap-2">
                  <code className="flex-1 bg-dark-800 border border-dark-500 rounded-lg px-3 py-2 text-sm font-mono text-dark-50">
                    {sftpPassword}
                  </code>
                  <button
                    onClick={() => copyToClipboard(sftpPassword, "sftp_password")}
                    className="shrink-0 px-3 py-2 bg-dark-700 text-dark-200 rounded-lg text-xs hover:bg-dark-600 transition-colors"
                  >
                    {copied === "sftp_password" ? "Copied!" : "Copy"}
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* WAF (ModSecurity) */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Web Application Firewall</h2>
            <div className="flex items-center gap-2">
              {site.waf_enabled && (
                <span className={`text-[10px] font-mono ${site.waf_mode === "prevention" ? "text-danger-400" : "text-warn-400"}`}>
                  {site.waf_mode === "prevention" ? "Blocking" : "Detection"}
                </span>
              )}
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                site.waf_enabled ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
              }`}>
                {site.waf_enabled ? "Active" : "Off"}
              </span>
            </div>
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-dark-200">
              ModSecurity WAF with OWASP Core Rule Set. Protects against SQL injection, XSS, RCE, and other OWASP Top 10 attacks. Start in Detection mode to monitor without blocking.
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <button
                disabled={wafToggling}
                onClick={async () => {
                  setWafToggling(true);
                  setWafMsg("");
                  try {
                    const result = await api.put<{ waf_enabled: boolean; waf_mode: string }>(`/sites/${id}/waf`, {
                      enabled: !site.waf_enabled,
                      mode: site.waf_enabled ? "detection" : "detection",
                    });
                    setSite(s => s ? { ...s, waf_enabled: result.waf_enabled, waf_mode: result.waf_mode } : s);
                    setWafMsg(site.waf_enabled ? "WAF disabled" : "WAF enabled (detection mode)");
                  } catch (e) {
                    setWafMsg(e instanceof Error ? e.message : "Toggle failed");
                  } finally {
                    setWafToggling(false);
                  }
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                  site.waf_enabled
                    ? "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                    : "bg-rust-500 text-white hover:bg-rust-600"
                }`}
              >
                {wafToggling ? "..." : site.waf_enabled ? "Disable WAF" : "Enable WAF"}
              </button>
              {site.waf_enabled && (
                <>
                  <button
                    disabled={wafToggling}
                    onClick={async () => {
                      setWafToggling(true);
                      setWafMsg("");
                      const newMode = site.waf_mode === "prevention" ? "detection" : "prevention";
                      try {
                        const result = await api.put<{ waf_enabled: boolean; waf_mode: string }>(`/sites/${id}/waf`, {
                          enabled: true,
                          mode: newMode,
                        });
                        setSite(s => s ? { ...s, waf_mode: result.waf_mode } : s);
                        setWafMsg(`Switched to ${newMode} mode`);
                      } catch (e) {
                        setWafMsg(e instanceof Error ? e.message : "Mode switch failed");
                      } finally {
                        setWafToggling(false);
                      }
                    }}
                    className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50 ${
                      site.waf_mode === "prevention"
                        ? "bg-danger-500/10 text-danger-400 hover:bg-danger-500/20"
                        : "bg-warn-500/10 text-warn-400 hover:bg-warn-500/20"
                    }`}
                  >
                    {site.waf_mode === "prevention" ? "Switch to Detection" : "Switch to Prevention"}
                  </button>
                  <button
                    disabled={wafLogsLoading}
                    onClick={async () => {
                      setWafLogsLoading(true);
                      try {
                        const result = await api.get<{ events: typeof wafLogs }>(`/sites/${id}/waf/logs`);
                        setWafLogs(result.events || []);
                      } catch { setWafLogs(null); }
                      finally { setWafLogsLoading(false); }
                    }}
                    className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                  >
                    {wafLogsLoading ? "Loading..." : "View Events"}
                  </button>
                </>
              )}
              {wafMsg && (
                <span className={`text-xs ${wafMsg.includes("failed") || wafMsg.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {wafMsg}
                </span>
              )}
            </div>
            {!wafLogsLoading && wafLogs !== null && wafLogs.length === 0 && (
              <p className="text-xs text-dark-300 mt-2">No WAF events recorded. Events appear when the firewall detects suspicious requests.</p>
            )}
            {wafLogs && wafLogs.length > 0 && (
              <div className="mt-3 bg-dark-900 rounded-lg border border-dark-600 overflow-x-auto max-h-64 overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-dark-900">
                    <tr className="border-b border-dark-600">
                      <th className="text-left px-3 py-2 text-dark-300 font-mono">Time</th>
                      <th className="text-left px-3 py-2 text-dark-300 font-mono">IP</th>
                      <th className="text-left px-3 py-2 text-dark-300 font-mono">URI</th>
                      <th className="text-left px-3 py-2 text-dark-300 font-mono">Rule</th>
                      <th className="text-left px-3 py-2 text-dark-300 font-mono">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-dark-700">
                    {wafLogs.map((evt, i) => (
                      <tr key={i} className="hover:bg-dark-800/50">
                        <td className="px-3 py-1.5 text-dark-200 font-mono whitespace-nowrap">{evt.timestamp?.slice(0, 19) || "-"}</td>
                        <td className="px-3 py-1.5 text-dark-200 font-mono">{evt.client_ip || "-"}</td>
                        <td className="px-3 py-1.5 text-dark-200 font-mono truncate max-w-[200px]">{evt.uri || "-"}</td>
                        <td className="px-3 py-1.5 text-warn-400 truncate max-w-[250px]">{evt.rule_message || "-"}</td>
                        <td className="px-3 py-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                            evt.action === "blocked" ? "bg-danger-500/15 text-danger-400" : "bg-dark-600 text-dark-200"
                          }`}>{evt.action}</span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Security Headers (CSP) */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
        <div className="px-5 py-4 border-b border-dark-600">
          <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Security Headers</h2>
          <p className="text-xs text-dark-200 mt-1">Content-Security-Policy and Permissions-Policy headers per site</p>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-sm font-medium text-dark-100 mb-1">Content-Security-Policy</label>
            <textarea
              value={cspPolicy}
              onChange={(e) => setCspPolicy(e.target.value)}
              placeholder="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;"
              rows={3}
              className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
            />
            <div className="flex flex-wrap gap-2 mt-2">
              {[
                { label: "WordPress", value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self';" },
                { label: "SPA", value: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https:; font-src 'self';" },
                { label: "Strict", value: "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; base-uri 'self'; form-action 'self';" },
              ].map(preset => (
                <button key={preset.label} onClick={() => setCspPolicy(preset.value)}
                  className="px-2 py-1 bg-dark-700 text-dark-200 rounded text-xs hover:bg-dark-600 transition-colors"
                >{preset.label}</button>
              ))}
              {cspPolicy && <button onClick={() => setCspPolicy("")} className="px-2 py-1 bg-dark-700 text-dark-200 rounded text-xs hover:bg-dark-600">Clear</button>}
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-dark-100 mb-1">Permissions-Policy</label>
            <input
              type="text"
              value={permsPolicy}
              onChange={(e) => setPermsPolicy(e.target.value)}
              placeholder="camera=(), microphone=(), geolocation=()"
              className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
            />
          </div>
          {headersMsg && <p className={`text-xs ${headersMsg.includes("Saved") ? "text-rust-400" : "text-danger-400"}`}>{headersMsg}</p>}
          <button
            onClick={async () => {
              setHeadersSaving(true); setHeadersMsg("");
              try {
                await api.put(`/sites/${id}/security-headers`, {
                  csp_policy: cspPolicy || null,
                  permissions_policy: permsPolicy || null,
                });
                setSite(s => s ? { ...s, csp_policy: cspPolicy || null, permissions_policy: permsPolicy || null } : s);
                setHeadersMsg("Saved - nginx reloaded");
              } catch (e) { setHeadersMsg(e instanceof Error ? e.message : "Failed"); }
              finally { setHeadersSaving(false); }
            }}
            disabled={headersSaving}
            className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
          >{headersSaving ? "Saving..." : "Save Headers"}</button>
        </div>
      </div>

      {/* Bot Protection */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
        <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
          <div>
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Bot Protection</h2>
            <p className="text-xs text-dark-200 mt-1">Block scrapers and bad bots. Legitimate search engines (Google, Bing) are always allowed.</p>
          </div>
          <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
            botMode !== "off" ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
          }`}>
            {botMode === "off" ? "Off" : botMode === "rate-limit" ? "Rate Limit" : botMode === "challenge" ? "JS Challenge" : "Block"}
          </span>
        </div>
        <div className="p-5 space-y-3">
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[
              { mode: "off", label: "Off", desc: "No bot protection" },
              { mode: "rate-limit", label: "Rate Limit", desc: "5 req/s per IP for all traffic" },
              { mode: "challenge", label: "JS Challenge", desc: "Browser verification via cookie" },
              { mode: "block", label: "Block", desc: "Block known bad bot user-agents" },
            ].map(opt => (
              <button
                key={opt.mode}
                onClick={async () => {
                  setBotSaving(true); setBotMsg("");
                  try {
                    await api.put(`/sites/${id}/bot-protection`, { mode: opt.mode });
                    setBotMode(opt.mode);
                    setSite(s => s ? { ...s, bot_protection: opt.mode } : s);
                    setBotMsg(`Bot protection: ${opt.label}`);
                  } catch (e) { setBotMsg(e instanceof Error ? e.message : "Failed"); }
                  finally { setBotSaving(false); }
                }}
                disabled={botSaving}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  botMode === opt.mode
                    ? "border-rust-500 bg-rust-500/10"
                    : "border-dark-500 hover:border-dark-400"
                }`}
              >
                <div className="text-sm font-medium text-dark-50">{opt.label}</div>
                <div className="text-xs text-dark-300 mt-0.5">{opt.desc}</div>
              </button>
            ))}
          </div>
          {botMsg && <p className="text-xs text-rust-400">{botMsg}</p>}
        </div>
      </div>

      {/* Image Optimization */}
      {site.status === "active" && (site.runtime === "php" || site.runtime === "static") && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Image Optimization</h2>
          </div>
          <div className="p-5 space-y-4">
            <p className="text-sm text-dark-200">
              Convert images to WebP or AVIF for smaller file sizes and faster page loads. Original files are preserved - optimized versions are served automatically by nginx.
            </p>
            <div className="flex items-center gap-3 flex-wrap">
              <button
                disabled={imgOptRunning}
                onClick={async () => {
                  setImgOptRunning(true);
                  setImgOptResult(null);
                  try {
                    const result = await api.post<typeof imgOptResult>(`/sites/${id}/optimize-images`, { format: "webp", quality: 80 });
                    setImgOptResult(result);
                  } catch (e) {
                    setImgOptResult({ converted: 0, total_images: 0, saved_mb: "0", format: "error" });
                  } finally {
                    setImgOptRunning(false);
                  }
                }}
                className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
              >
                {imgOptRunning ? "Converting..." : "Convert to WebP"}
              </button>
              <button
                disabled={imgOptRunning}
                onClick={async () => {
                  setImgOptRunning(true);
                  setImgOptResult(null);
                  try {
                    const result = await api.post<typeof imgOptResult>(`/sites/${id}/optimize-images`, { format: "avif", quality: 70 });
                    setImgOptResult(result);
                  } catch (e) {
                    setImgOptResult({ converted: 0, total_images: 0, saved_mb: "0", format: "error" });
                  } finally {
                    setImgOptRunning(false);
                  }
                }}
                className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
              >
                {imgOptRunning ? "..." : "Convert to AVIF"}
              </button>
              {imgOptResult && imgOptResult.format !== "error" && (
                <span className="text-xs text-rust-400">
                  {imgOptResult.converted}/{imgOptResult.total_images} converted, {imgOptResult.saved_mb}MB saved ({imgOptResult.format?.toUpperCase()})
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Staging Environment */}
      {site.status === "active" && !site.parent_site_id && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Staging Environment</h2>
            {staging?.exists && staging.site && (
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${statusColors[staging.site.status] || "bg-dark-700 text-dark-200"}`}>
                {staging.site.status}
              </span>
            )}
          </div>
          <div className="p-5">
            {staging?.exists && staging.site ? (
              <div className="space-y-4">
                {/* Staging info */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  <div>
                    <p className="text-xs font-medium text-dark-200 mb-1">Domain</p>
                    <a
                      href={`http://${staging.site.domain}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-rust-400 hover:text-rust-300 font-mono"
                    >
                      {staging.site.domain}
                    </a>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-dark-200 mb-1">Last Synced</p>
                    <p className="text-sm text-dark-50">
                      {staging.site.synced_at ? formatDate(staging.site.synced_at) : "Never"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-dark-200 mb-1">Disk Usage</p>
                    <p className="text-sm text-dark-50">
                      {staging.disk_usage_bytes != null
                        ? staging.disk_usage_bytes < 1048576
                          ? `${Math.round(staging.disk_usage_bytes / 1024)} KB`
                          : `${(staging.disk_usage_bytes / 1048576).toFixed(1)} MB`
                        : "-"}
                    </p>
                  </div>
                  <div>
                    <p className="text-xs font-medium text-dark-200 mb-1">Created</p>
                    <p className="text-sm text-dark-50">{formatDate(staging.site.created_at)}</p>
                  </div>
                </div>

                {/* Inline staging confirmation bar */}
                {pendingConfirm && (
                  <div className={`px-4 py-3 rounded-lg border flex items-center justify-between ${
                    pendingConfirm.type === "staging_delete" ? "border-danger-500/30 bg-danger-500/5" : "border-warn-500/30 bg-warn-500/5"
                  }`}>
                    <span className={`text-xs font-mono ${pendingConfirm.type === "staging_delete" ? "text-danger-400" : "text-warn-400"}`}>
                      {pendingConfirm.label}
                    </span>
                    <div className="flex items-center gap-2 shrink-0 ml-4">
                      <button onClick={executeConfirm} className="px-3 py-1.5 bg-danger-500 text-white text-xs font-bold uppercase tracking-wider hover:bg-danger-600 transition-colors">
                        Confirm
                      </button>
                      <button onClick={() => setPendingConfirm(null)} className="px-3 py-1.5 bg-dark-600 text-dark-200 text-xs font-bold uppercase tracking-wider hover:bg-dark-500 transition-colors">
                        Cancel
                      </button>
                    </div>
                  </div>
                )}

                {/* Staging actions */}
                <div className="flex items-center gap-2 pt-2 border-t border-dark-600">
                  <button
                    disabled={stagingLoading}
                    onClick={async () => {
                      setStagingLoading(true);
                      setStagingMessage("");
                      try {
                        await api.post(`/sites/${id}/staging/sync`);
                        setStagingMessage("Files synced from production");
                        fetchStaging();
                      } catch (e) {
                        setStagingMessage(e instanceof Error ? e.message : "Sync failed");
                      } finally {
                        setStagingLoading(false);
                      }
                    }}
                    className="px-3 py-1.5 bg-rust-500 text-white rounded-lg text-xs font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
                  >
                    {stagingLoading ? "Working..." : "Sync from Prod"}
                  </button>
                  <button
                    disabled={stagingLoading}
                    onClick={() => setPendingConfirm({ type: "staging_push", label: "This will overwrite production files with staging files. Continue?" })}
                    className="px-3 py-1.5 bg-warn-600 text-white rounded-lg text-xs font-medium hover:bg-warn-600 disabled:opacity-50 transition-colors"
                  >
                    Push to Prod
                  </button>
                  <Link
                    to={`/sites/${staging.site.id}/files`}
                    className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded-lg text-xs font-medium hover:bg-dark-600 transition-colors"
                  >
                    Files
                  </Link>
                  <Link
                    to={`/terminal?site=${staging.site.id}`}
                    className="px-3 py-1.5 bg-dark-700 text-dark-100 rounded-lg text-xs font-medium hover:bg-dark-600 transition-colors"
                  >
                    Terminal
                  </Link>
                  <div className="flex-1" />
                  <button
                    disabled={stagingLoading}
                    onClick={() => setPendingConfirm({ type: "staging_delete", label: "Delete this staging environment? This cannot be undone." })}
                    className="px-3 py-1.5 bg-danger-500/10 text-danger-400 rounded-lg text-xs font-medium hover:bg-danger-500/20 transition-colors"
                  >
                    Delete Staging
                  </button>
                </div>

                {stagingMessage && (
                  <p className={`text-xs ${stagingMessage.includes("failed") || stagingMessage.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                    {stagingMessage}
                  </p>
                )}
              </div>
            ) : (
              <div className="space-y-3">
                <p className="text-sm text-dark-200">
                  Create a staging copy of this site's files to test changes before going live.
                  Only files are cloned - if this site has a database attached, staging reads
                  and writes that SAME live database; it is not isolated.
                </p>
                {pendingConfirm && pendingConfirm.type === "staging_create_db_ack" && (
                  <div className="px-4 py-3 rounded-lg border border-warn-500/30 bg-warn-500/5 flex items-center justify-between">
                    <span className="text-xs font-mono text-warn-400">{pendingConfirm.label}</span>
                    <div className="flex items-center gap-2 shrink-0 ml-4">
                      <button onClick={executeConfirm} className="px-3 py-1.5 bg-warn-600 text-white text-xs font-bold uppercase tracking-wider hover:bg-warn-600 transition-colors">
                        Continue Anyway
                      </button>
                      <button onClick={() => setPendingConfirm(null)} className="px-3 py-1.5 bg-dark-600 text-dark-200 text-xs font-bold uppercase tracking-wider hover:bg-dark-500 transition-colors">
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
                {showStagingForm ? (
                  <div className="flex items-end gap-3">
                    <div className="flex-1">
                      <label className="block text-xs font-medium text-dark-200 mb-1">
                        Staging Domain
                      </label>
                      <input
                        type="text"
                        value={stagingDomain}
                        onChange={(e) => setStagingDomain(e.target.value)}
                        placeholder={`staging.${site.domain}`}
                        className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                      />
                    </div>
                    <button
                      disabled={stagingLoading}
                      onClick={async () => {
                        setStagingLoading(true);
                        setStagingMessage("");
                        try {
                          await api.post(`/sites/${id}/staging`, {
                            domain: stagingDomain || undefined,
                          });
                          fetchStaging();
                          setShowStagingForm(false);
                          setStagingMessage("Staging environment created");
                        } catch (e) {
                          const message = e instanceof Error ? e.message : "Creation failed";
                          if (message.includes("attached database")) {
                            setPendingConfirm({ type: "staging_create_db_ack", label: `${message} Continue anyway?` });
                          } else {
                            setStagingMessage(message);
                          }
                        } finally {
                          setStagingLoading(false);
                        }
                      }}
                      className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
                    >
                      {stagingLoading ? "Creating..." : "Create"}
                    </button>
                    <button
                      onClick={() => setShowStagingForm(false)}
                      className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  /* See the Clone control above - a staging environment is a new
                     domain and `ensure_claimable` refuses it for a client. */
                  !isClient && (
                    <button
                      onClick={() => setShowStagingForm(true)}
                      className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors"
                    >
                      Create Staging
                    </button>
                  )
                )}
                {stagingMessage && (
                  <p className={`text-xs ${stagingMessage.includes("failed") || stagingMessage.includes("Failed") ? "text-danger-400" : "text-rust-400"}`}>
                    {stagingMessage}
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Redirect Rules */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button
            onClick={() => setShowRedirects(!showRedirects)}
            className="w-full px-5 py-4 border-b border-dark-600 flex items-center justify-between text-left"
          >
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Redirect Rules</h2>
            <div className="flex items-center gap-2">
              {redirects.length > 0 && (
                <span className="text-xs text-dark-200">{redirects.length} rule{redirects.length !== 1 ? "s" : ""}</span>
              )}
              <svg className={`w-4 h-4 text-dark-300 transition-transform ${showRedirects ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
              </svg>
            </div>
          </button>
          {showRedirects && (
            <div className="p-5 space-y-4">
              {/* Existing redirects */}
              {redirects.length > 0 && (
                <div className="space-y-2">
                  {redirects.map((r, i) => (
                    <div key={i} className="flex items-center justify-between bg-dark-900 rounded-lg px-4 py-3">
                      <div className="flex items-center gap-3 text-sm">
                        <span className={`px-2 py-0.5 rounded text-xs font-medium ${r.type === "301" ? "bg-rust-500/10 text-rust-400" : "bg-warn-500/10 text-warn-400"}`}>
                          {r.type}
                        </span>
                        <span className="text-dark-100 font-mono">{r.source}</span>
                        <svg className="w-4 h-4 text-dark-300" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                        </svg>
                        <span className="text-dark-200 font-mono truncate max-w-[300px]">{r.target}</span>
                      </div>
                      <button
                        onClick={async () => {
                          try {
                            await api.post(`/sites/${id}/redirects/remove`, { source: r.source });
                            loadRedirects();
                            setRedirectMsg("Redirect removed");
                          } catch (e) {
                            setRedirectMsg(e instanceof Error ? e.message : "Failed");
                          }
                        }}
                        className="p-1 text-dark-300 hover:text-danger-500 transition-colors"
                        title="Remove"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Add redirect form */}
              <div className="flex items-end gap-3">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-dark-200 mb-1">Source Path</label>
                  <input
                    type="text"
                    value={redirectSource}
                    onChange={(e) => setRedirectSource(e.target.value)}
                    placeholder="/old-page"
                    className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <div className="flex-1">
                  <label className="block text-xs font-medium text-dark-200 mb-1">Target URL</label>
                  <input
                    type="text"
                    value={redirectTarget}
                    onChange={(e) => setRedirectTarget(e.target.value)}
                    placeholder="https://example.com/new-page"
                    className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <div className="w-24">
                  <label className="block text-xs font-medium text-dark-200 mb-1">Type</label>
                  <select
                    value={redirectType}
                    onChange={(e) => setRedirectType(e.target.value)}
                    className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm bg-dark-800 focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  >
                    <option value="301">301</option>
                    <option value="302">302</option>
                  </select>
                </div>
                <button
                  onClick={async () => {
                    if (!redirectSource || !redirectTarget) return;
                    setRedirectMsg("");
                    try {
                      await api.post(`/sites/${id}/redirects`, {
                        source: redirectSource,
                        target: redirectTarget,
                        redirect_type: redirectType,
                      });
                      setRedirectSource("");
                      setRedirectTarget("");
                      loadRedirects();
                      setRedirectMsg("Redirect added");
                    } catch (e) {
                      setRedirectMsg(e instanceof Error ? e.message : "Failed");
                    }
                  }}
                  className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors"
                >
                  Add
                </button>
              </div>

              {redirectMsg && (
                <p className={`text-xs ${redirectMsg.includes("Failed") || redirectMsg.includes("failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {redirectMsg}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Password Protection */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button
            onClick={() => setShowProtect(!showProtect)}
            className="w-full px-5 py-4 border-b border-dark-600 flex items-center justify-between text-left"
          >
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Password Protection</h2>
            <div className="flex items-center gap-2">
              {protectedPaths.length > 0 && (
                <span className="text-xs text-dark-200">{protectedPaths.length} path{protectedPaths.length !== 1 ? "s" : ""}</span>
              )}
              <svg className={`w-4 h-4 text-dark-300 transition-transform ${showProtect ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
              </svg>
            </div>
          </button>
          {showProtect && (
            <div className="p-5 space-y-4">
              {/* Current protection */}
              {protectedPaths.length > 0 && (
                <div className="space-y-2">
                  <div className="flex items-center gap-4 text-xs text-dark-200 mb-2">
                    <span>Protected paths: {protectedPaths.join(", ")}</span>
                    <span>Users: {protectedUsers.join(", ")}</span>
                  </div>
                  {protectedPaths.map((p, i) => (
                    <div key={i} className="flex items-center justify-between bg-dark-900 rounded-lg px-4 py-3">
                      <div className="flex items-center gap-2 text-sm">
                        <svg className="w-4 h-4 text-warn-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z" />
                        </svg>
                        <span className="text-dark-100 font-mono">{p}</span>
                      </div>
                      <button
                        onClick={async () => {
                          try {
                            await api.post(`/sites/${id}/password-protect/remove`, { path: p });
                            loadProtected();
                            setProtectMsg("Protection removed");
                          } catch (e) {
                            setProtectMsg(e instanceof Error ? e.message : "Failed");
                          }
                        }}
                        className="p-1 text-dark-300 hover:text-danger-500 transition-colors"
                        title="Remove"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Add protection form */}
              <div className="flex items-end gap-3">
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Path</label>
                  <input
                    type="text"
                    value={protectPath}
                    onChange={(e) => setProtectPath(e.target.value)}
                    placeholder="/"
                    className="w-32 px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Username</label>
                  <input
                    type="text"
                    value={protectUser}
                    onChange={(e) => setProtectUser(e.target.value)}
                    placeholder="admin"
                    className="w-36 px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-dark-200 mb-1">Password</label>
                  <input
                    type="password"
                    value={protectPass}
                    onChange={(e) => setProtectPass(e.target.value)}
                    placeholder="password"
                    className="w-36 px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <button
                  onClick={async () => {
                    if (!protectUser || !protectPass) return;
                    setProtectMsg("");
                    try {
                      await api.post(`/sites/${id}/password-protect`, {
                        path: protectPath || "/",
                        username: protectUser,
                        password: protectPass,
                      });
                      setProtectUser("");
                      setProtectPass("");
                      loadProtected();
                      setProtectMsg("Protection enabled");
                    } catch (e) {
                      setProtectMsg(e instanceof Error ? e.message : "Failed");
                    }
                  }}
                  className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors"
                >
                  Protect
                </button>
              </div>

              {protectMsg && (
                <p className={`text-xs ${protectMsg.includes("Failed") || protectMsg.includes("failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {protectMsg}
                </p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Block PHP execution in upload folders */}
      {site.status === "active" && site.runtime === "php" && (() => {
        const saved = site.php_no_exec_dirs ?? null;
        const dirty = JSON.stringify(noExecDirs) !== JSON.stringify(saved ?? []);
        const newDir = newNoExecDir.trim();
        const newDirError = newDir ? validateNoExecDir(newDir) : "";
        const addDir = () => {
          if (!newDir || newDirError) return;
          if (noExecDirs.includes(newDir)) {
            setNoExecMsg({ text: `${newDir} is already in the list`, error: true });
            return;
          }
          setNoExecDirs([...noExecDirs, newDir]);
          setNewNoExecDir("");
          setNoExecMsg(null);
        };
        return (
          <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
            <div className="px-5 py-4 border-b border-dark-600 flex items-center justify-between">
              <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">
                Block PHP execution in upload folders
              </h2>
              <span className={`inline-flex px-2.5 py-0.5 rounded-full text-xs font-medium ${
                saved && saved.length > 0 ? "bg-rust-500/10 text-rust-400" : "bg-dark-700 text-dark-300"
              }`}>
                {saved && saved.length > 0 ? `${saved.length} folder${saved.length !== 1 ? "s" : ""}` : "Off"}
              </span>
            </div>
            <div className="p-5 space-y-4">
              <p className="text-sm text-dark-200">
                PHP files inside these folders (and below them) are refused with a 403 instead of being
                run, so an uploaded script cannot execute. Paths are relative to the site root.
              </p>
              <p className="text-xs text-dark-400">
                Defaults: <span className="font-mono">{DEFAULT_NO_EXEC_DIRS.join(", ")}</span>
              </p>

              {noExecDirs.length > 0 ? (
                <div className="space-y-2">
                  {noExecDirs.map((dir) => (
                    <div key={dir} className="flex items-center justify-between bg-dark-900 rounded-lg px-4 py-2">
                      <span className="text-sm text-dark-100 font-mono">{dir}</span>
                      <button
                        type="button"
                        onClick={() => setNoExecDirs(noExecDirs.filter((d) => d !== dir))}
                        disabled={savingNoExec}
                        className="p-1 text-dark-300 hover:text-danger-500 transition-colors disabled:opacity-50"
                        title="Remove"
                        aria-label={`Remove ${dir}`}
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-dark-300">No folder in the list.</p>
              )}

              <div className="flex items-end gap-3">
                <div className="flex-1 max-w-md">
                  <label htmlFor="no-exec-dir" className="block text-xs font-medium text-dark-200 mb-1">Folder</label>
                  <input
                    id="no-exec-dir"
                    type="text"
                    value={newNoExecDir}
                    onChange={(e) => setNewNoExecDir(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") addDir(); }}
                    placeholder="/wp-content/uploads"
                    spellCheck={false}
                    className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <button
                  type="button"
                  onClick={addDir}
                  disabled={!newDir || !!newDirError || savingNoExec}
                  className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                >
                  Add
                </button>
              </div>
              {newDirError && <p className="text-xs text-danger-400">{newDirError}</p>}

              <div className="flex flex-wrap items-center gap-3">
                <button
                  type="button"
                  disabled={savingNoExec || !dirty}
                  onClick={() => saveNoExec(noExecDirs, "Saved")}
                  className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors"
                >
                  {savingNoExec ? "Saving..." : "Save"}
                </button>
                <button
                  type="button"
                  disabled={savingNoExec}
                  onClick={() => saveNoExec("defaults", "Default folders applied")}
                  className="px-4 py-2 bg-dark-700 text-dark-100 rounded-lg text-sm font-medium hover:bg-dark-600 disabled:opacity-50 transition-colors"
                >
                  Apply defaults
                </button>
                <button
                  type="button"
                  disabled={savingNoExec || saved === null}
                  onClick={() => saveNoExec(null, "PHP execution is no longer blocked in any folder")}
                  className="px-4 py-2 bg-warn-500/10 text-warn-400 rounded-lg text-sm font-medium hover:bg-warn-500/20 disabled:opacity-50 transition-colors"
                >
                  Disable
                </button>
                {noExecMsg && (
                  <span className={`text-xs ${noExecMsg.error ? "text-danger-400" : "text-rust-400"}`}>
                    {noExecMsg.text}
                  </span>
                )}
              </div>
            </div>
          </div>
        );
      })()}

      {/* Domain Aliases */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button
            onClick={() => setShowAliases(!showAliases)}
            className="w-full px-5 py-4 border-b border-dark-600 flex items-center justify-between text-left"
          >
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Domain Aliases</h2>
            <div className="flex items-center gap-2">
              {aliases.length > 0 && (
                <span className="text-xs text-dark-200">{aliases.length} alias{aliases.length !== 1 ? "es" : ""}</span>
              )}
              <svg className={`w-4 h-4 text-dark-300 transition-transform ${showAliases ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 8.25l-7.5 7.5-7.5-7.5" />
              </svg>
            </div>
          </button>
          {showAliases && (
            <div className="p-5 space-y-4">
              <p className="text-xs text-dark-300">
                Additional domains that serve the same site content. DNS must point to this server.
              </p>

              {/* Current aliases */}
              {aliases.length > 0 && (
                <div className="space-y-2">
                  {aliases.map((alias, i) => (
                    <div key={i} className="flex items-center justify-between bg-dark-900 rounded-lg px-4 py-3">
                      <span className="text-sm text-dark-100 font-mono">{alias}</span>
                      <button
                        onClick={async () => {
                          try {
                            await api.post(`/sites/${id}/aliases/remove`, { alias });
                            loadAliases();
                            setAliasMsg("Alias removed");
                          } catch (e) {
                            setAliasMsg(e instanceof Error ? e.message : "Failed");
                          }
                        }}
                        className="p-1 text-dark-300 hover:text-danger-500 transition-colors"
                        title="Remove"
                      >
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>
              )}

              {/* Add alias form - an alias IS a new domain
                  (`ensure_claimable`), so it is not a client's to add. Existing
                  aliases stay listed above: they are part of the site they hold. */}
              {!isClient && (
              <div className="flex items-end gap-3">
                <div className="flex-1">
                  <label className="block text-xs font-medium text-dark-200 mb-1">Domain Alias</label>
                  <input
                    type="text"
                    value={newAlias}
                    onChange={(e) => setNewAlias(e.target.value)}
                    placeholder="www.example.com"
                    className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none"
                  />
                </div>
                <button
                  onClick={async () => {
                    if (!newAlias.trim()) return;
                    setAliasMsg("");
                    try {
                      await api.post(`/sites/${id}/aliases`, { alias: newAlias.trim() });
                      setNewAlias("");
                      loadAliases();
                      setAliasMsg("Alias added");
                    } catch (e) {
                      setAliasMsg(e instanceof Error ? e.message : "Failed");
                    }
                  }}
                  disabled={!newAlias.trim()}
                  className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Add Alias
                </button>
              </div>
              )}

              {aliasMsg && (
                <p className={`text-xs ${aliasMsg.includes("Failed") || aliasMsg.includes("failed") ? "text-danger-400" : "text-rust-400"}`}>
                  {aliasMsg}
                </p>
              )}

              {/* Canonical host: every other served name 301s to the chosen one. */}
              {(() => {
                const wwwName = `www.${site.domain}`.toLowerCase();
                const served = [...aliases, ...(site.aliases ?? [])].map((a) => a.toLowerCase());
                const wwwServed = served.includes(wwwName);
                const current = site.canonical_host ?? null;
                const choices: { value: "www" | "apex" | null; label: string; title?: string; disabled?: boolean }[] = [
                  { value: null, label: "None" },
                  {
                    value: "www",
                    label: `www (${wwwName})`,
                    disabled: !wwwServed,
                    title: wwwServed ? undefined : `Add ${wwwName} as an alias first`,
                  },
                  { value: "apex", label: `apex (${site.domain})` },
                ];
                return (
                  <div className="pt-4 border-t border-dark-600 space-y-2">
                    <div className="text-xs font-medium text-dark-200">Canonical host</div>
                    <p className="text-xs text-dark-400">
                      Redirect every other name of this site (301) to one address.
                    </p>
                    <div className="flex flex-wrap items-center gap-2">
                      {choices.map((c) => (
                        <button
                          key={c.label}
                          type="button"
                          disabled={savingCanonical || c.disabled || current === c.value}
                          title={c.title}
                          onClick={() => setCanonicalHost(c.value)}
                          className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors disabled:cursor-not-allowed ${
                            current === c.value
                              ? "bg-rust-500 text-white"
                              : "bg-dark-700 text-dark-100 hover:bg-dark-600 disabled:opacity-50"
                          }`}
                        >
                          {c.label}
                        </button>
                      ))}
                      {savingCanonical && <span className="text-xs text-dark-200">Saving...</span>}
                    </div>
                    {canonicalMsg && (
                      <p className={`text-xs ${canonicalMsg.error ? "text-danger-400" : "text-rust-400"}`}>
                        {canonicalMsg.text}
                      </p>
                    )}
                  </div>
                );
              })()}
            </div>
          )}
        </div>
      )}

      {/* Access Logs */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button onClick={() => { setShowAccessLogs(!showAccessLogs); if (!showAccessLogs) loadLogs(logType === "php" ? "access" : logType); }}
            className="w-full px-5 py-4 flex items-center justify-between hover:bg-dark-700/30 transition-colors">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Access Logs</h2>
            <svg className={`w-4 h-4 text-dark-300 transition-transform ${showAccessLogs ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
            </svg>
          </button>
          {showAccessLogs && (
            <div className="border-t border-dark-600">
              <div className="flex items-center justify-between px-5 py-2 bg-dark-900">
                <div className="flex gap-2">
                  <button onClick={() => { setLogType("access"); loadLogs("access"); }}
                    className={`px-2 py-1 rounded text-xs font-medium ${logType === "access" ? "bg-rust-500/15 text-rust-400" : "text-dark-300 hover:text-dark-100"}`}>Access</button>
                  <button onClick={() => { setLogType("error"); loadLogs("error"); }}
                    className={`px-2 py-1 rounded text-xs font-medium ${logType === "error" ? "bg-danger-400/15 text-danger-400" : "text-dark-300 hover:text-dark-100"}`}>Error</button>
                  {site.runtime === "php" && site.web_server === "apache" && (
                    <button onClick={() => { setLogType("apache_error"); loadLogs("apache_error"); }}
                      className={`px-2 py-1 rounded text-xs font-medium ${logType === "apache_error" ? "bg-danger-400/15 text-danger-400" : "text-dark-300 hover:text-dark-100"}`}>Apache error log</button>
                  )}
                  {site.runtime === "php" && (
                    <button onClick={() => { setLogType("php"); loadPhpErrors(); }}
                      className={`px-2 py-1 rounded text-xs font-medium ${logType === "php" ? "bg-warn-500/15 text-warn-400" : "text-dark-300 hover:text-dark-100"}`}>PHP Errors</button>
                  )}
                </div>
                <button onClick={() => logType === "php" ? loadPhpErrors() : loadLogs(logType)} className="text-xs text-rust-400 hover:text-rust-300">
                  {logsLoading ? "Loading..." : "Refresh"}
                </button>
              </div>
              <pre className="p-4 text-[11px] font-mono text-dark-200 bg-dark-950 max-h-80 overflow-y-auto overflow-x-auto whitespace-pre-wrap">
                {logsLoading ? "Loading logs..." : (logType === "access" ? accessLogs : logType === "error" ? errorLogs : logType === "apache_error" ? apacheErrorLogs : phpErrors) || "No logs available"}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Traffic Stats */}
      {site.status === "active" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button onClick={() => { setShowStats(!showStats); if (!showStats) loadStats(); }}
            className="w-full px-5 py-4 flex items-center justify-between hover:bg-dark-700/30 transition-colors">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Traffic Stats</h2>
            <svg className={`w-4 h-4 text-dark-300 transition-transform ${showStats ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
            </svg>
          </button>
          {showStats && statsLoading && (
            <div className="border-t border-dark-600 p-5">
              <div className="animate-pulse space-y-3">
                <div className="grid grid-cols-3 gap-4">
                  <div className="h-12 bg-dark-700 rounded" />
                  <div className="h-12 bg-dark-700 rounded" />
                  <div className="h-12 bg-dark-700 rounded" />
                </div>
              </div>
            </div>
          )}
          {showStats && !statsLoading && stats && (
            <div className="border-t border-dark-600 p-5">
              <div className="grid grid-cols-3 gap-4 mb-4">
                <div className="text-center">
                  <p className="text-2xl font-bold text-dark-50">{stats.requests.toLocaleString()}</p>
                  <p className="text-xs text-dark-300">Requests</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-dark-50">{stats.unique_ips.toLocaleString()}</p>
                  <p className="text-xs text-dark-300">Unique IPs</p>
                </div>
                <div className="text-center">
                  <p className="text-2xl font-bold text-dark-50">{stats.bandwidth_mb} MB</p>
                  <p className="text-xs text-dark-300">Bandwidth</p>
                </div>
              </div>
              {stats.top_pages && stats.top_pages.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-2">Top Pages</h4>
                  <div className="space-y-1">
                    {stats.top_pages.map((p, i) => (
                      <div key={i} className="flex items-center justify-between text-xs">
                        <span className="text-dark-100 font-mono truncate flex-1">{p.path}</span>
                        <span className="text-dark-300 ml-2 font-mono">{p.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {stats.status_codes && Object.keys(stats.status_codes).length > 0 && (
                <div className="mt-4">
                  <h4 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-2">Status Codes</h4>
                  <div className="flex gap-3 flex-wrap">
                    {Object.entries(stats.status_codes).sort().map(([code, count]) => (
                      <div key={code} className={`px-2 py-1 rounded text-xs font-mono ${code.startsWith("2") ? "bg-rust-500/15 text-rust-400" : code.startsWith("3") ? "bg-accent-500/15 text-accent-400" : code.startsWith("4") ? "bg-warn-500/15 text-warn-400" : "bg-danger-500/15 text-danger-400"}`}>
                        {code}: {count}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* PHP Extensions */}
      {site?.runtime === "php" && (
        <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
          <button onClick={() => { setShowPhpExts(!showPhpExts); if (!showPhpExts) loadPhpExtensions(); }}
            className="w-full px-5 py-4 flex items-center justify-between hover:bg-dark-700/30 transition-colors">
            <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">PHP Extensions</h2>
            <svg className={`w-4 h-4 text-dark-300 transition-transform ${showPhpExts ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
            </svg>
          </button>
          {showPhpExts && phpExtsLoading && (
            <div className="border-t border-dark-600 p-5">
              <div className="animate-pulse space-y-3">
                <div className="h-4 bg-dark-700 rounded w-32" />
                <div className="flex flex-wrap gap-1.5">
                  {[1,2,3,4,5].map(i => <div key={i} className="h-6 w-16 bg-dark-700 rounded" />)}
                </div>
              </div>
            </div>
          )}
          {showPhpExts && !phpExtsLoading && phpExts && (
            <div className="border-t border-dark-600 p-5">
              <div className="mb-4">
                <h4 className="text-xs text-dark-300 uppercase font-mono mb-2">Installed ({phpExts.installed.length})</h4>
                <div className="flex flex-wrap gap-1.5">
                  {phpExts.installed.map(ext => (
                    <span key={ext} className="px-2 py-0.5 bg-rust-500/10 text-rust-400 rounded text-xs font-mono">{ext}</span>
                  ))}
                </div>
              </div>
              <div>
                <h4 className="text-xs text-dark-300 uppercase font-mono mb-2">Available to install</h4>
                <div className="flex flex-wrap gap-1.5">
                  {phpExts.available.filter(e => !phpExts.installed.includes(e)).map(ext => (
                    <button key={ext} disabled={installingExt === ext} onClick={async () => {
                      setInstallingExt(ext);
                      setExtMessage("");
                      try {
                        await api.post("/php/extensions/install", { version: site?.php_version, extension: ext });
                        loadPhpExtensions();
                      } catch (e) {
                        // Without this the spinner simply stopped and the
                        // extension stayed in "Available" - the operator's only
                        // clue that anything had gone wrong.
                        setExtMessage(e instanceof Error ? e.message : `Could not install ${ext}`);
                      }
                      finally { setInstallingExt(null); }
                    }} className="px-2 py-0.5 bg-dark-700 text-dark-200 rounded text-xs font-mono hover:bg-dark-600 disabled:opacity-50">
                      {installingExt === ext ? "..." : ext}
                    </button>
                  ))}
                </div>
                {extMessage && <p className="text-xs text-danger-400 mt-2">{extMessage}</p>}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Environment Variables */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-6">
        <button onClick={() => { setShowEnvVars(!showEnvVars); if (!showEnvVars) loadEnvVars(); }}
          className="w-full px-5 py-4 flex items-center justify-between hover:bg-dark-700/30 transition-colors">
          <h2 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">Environment Variables</h2>
          <svg className={`w-4 h-4 text-dark-300 transition-transform ${showEnvVars ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5" />
          </svg>
        </button>
        {showEnvVars && (
          <div className="border-t border-dark-600 p-5 space-y-2">
            {envVars.map((v, i) => (
              <div key={i} className="flex gap-2">
                <input value={v.key} onChange={e => { const n = [...envVars]; n[i] = { ...n[i], key: e.target.value }; setEnvVars(n); }}
                  placeholder="KEY" className="w-1/3 px-2 py-1.5 bg-dark-900 border border-dark-500 rounded text-xs font-mono text-dark-100 focus:ring-2 focus:ring-accent-500 outline-none" />
                <input value={v.value} onChange={e => { const n = [...envVars]; n[i] = { ...n[i], value: e.target.value }; setEnvVars(n); }}
                  placeholder="value" className="flex-1 px-2 py-1.5 bg-dark-900 border border-dark-500 rounded text-xs font-mono text-dark-100 focus:ring-2 focus:ring-accent-500 outline-none" />
                <button onClick={() => setEnvVars(envVars.filter((_, j) => j !== i))} className="text-danger-400 hover:text-danger-300 text-sm px-1">x</button>
              </div>
            ))}
            <div className="flex gap-2 items-center">
              <button onClick={() => setEnvVars([...envVars, { key: "", value: "" }])} className="text-xs text-rust-400 hover:text-rust-300">+ Add variable</button>
              <button disabled={savingEnv} onClick={async () => {
                setSavingEnv(true);
                setEnvMsg("");
                try {
                  await api.put(`/sites/${id}/env`, { vars: envVars.filter(v => v.key) });
                  setEnvMsg("Environment variables saved");
                } catch (e) { setEnvMsg(e instanceof Error ? e.message : "Save failed"); }
                finally { setSavingEnv(false); }
              }} className="px-3 py-1 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-50">
                {savingEnv ? "Saving..." : "Save"}
              </button>
              {envMsg && (
                <span className={`text-xs ${envMsg.includes("saved") ? "text-rust-400" : "text-danger-400"}`}>{envMsg}</span>
              )}
            </div>
            <p className="text-xs text-dark-300">Saves to .env file in the site root. Node.js/Python apps are auto-restarted.</p>
          </div>
        )}
      </div>

      {/* The SSL message used to render here - at the bottom of the whole page,
          far below the SSL card whose buttons produce it. It now renders inside
          that card instead (see the "SSL" row above). */}
    </div>
  );
}
