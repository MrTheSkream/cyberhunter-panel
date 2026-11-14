import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useServer } from "../context/ServerContext";
import { useAuth } from "../context/AuthContext";
import { isNavVisible, navFlagsFor } from "../data/navItems";
import { formatSize, formatRate, formatUptime, timeAgo } from "../utils/format";

interface SiteDetail {
  id: string;
  domain?: string;
  status: string;
  // A site the operator disabled is serving a maintenance response, not the
  // site. Counting it as active is the same mistake the vhost writers made.
  enabled?: boolean;
}

interface ActivityItem {
  action: string;
  target_name?: string;
  created_at: string;
}

interface TimelineEvent {
  type: string;
  detail: string;
  target?: string;
  created_at: string;
}

interface FleetServer {
  id: string;
  name: string;
  ip_address?: string;
  firing_alerts: number;
  active_incidents: number;
  sites: number;
  databases: number;
  cpu_pct?: number;
  mem_pct?: number;
  disk_pct?: number;
  status: string;
}

interface FleetOverview {
  servers: FleetServer[];
  total_servers: number;
  total_firing: number;
  total_incidents: number;
  total_sites: number;
}

interface DockerImage {
  size: number | string;
  Size?: number | string;
}

interface DockerImagesResponse {
  images?: DockerImage[];
}

interface MailQueueResponse {
  count?: number;
  queue?: unknown[];
}

interface DiskIoResponse {
  read_bytes_sec: number;
  write_bytes_sec: number;
}

interface UpdateInfo {
  /// Derived by the backend, not a presence check: the stored version outlives
  /// the release it names on any panel upgraded from the shell, so only this
  /// flag may gate the banner.
  update_available: boolean;
  update_available_version?: string;
  update_release_url?: string;
  current_version?: string;
}

function useCountUp(target: number, duration = 800): number {
  const [value, setValue] = useState(0);
  const prev = useRef(0);
  useEffect(() => {
    const start = prev.current;
    const diff = target - start;
    if (Math.abs(diff) < 0.5) { setValue(target); prev.current = target; return; }
    const steps = Math.max(Math.floor(duration / 16), 1);
    let step = 0;
    const timer = setInterval(() => {
      step++;
      const progress = step / steps;
      const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
      setValue(start + diff * eased);
      if (step >= steps) {
        setValue(target);
        prev.current = target;
        clearInterval(timer);
      }
    }, 16);
    return () => clearInterval(timer);
  }, [target, duration]);
  return value;
}

interface OnboardingStep {
  id: string;
  label: string;
  description: string;
  link: string;
  check: () => boolean;
}


interface SystemInfo {
  cpu_count: number;
  cpu_usage: number;
  cpu_model: string;
  cpu_temp: number | null;
  mem_total_mb: number;
  mem_used_mb: number;
  mem_usage_pct: number;
  swap_total_mb: number;
  swap_used_mb: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_usage_pct: number;
  uptime_secs: number;
  hostname: string;
  os: string;
  kernel: string;
  load_avg_1?: number;
  load_avg_5?: number;
  load_avg_15?: number;
  process_count: number;
}

interface Process {
  pid: number;
  name: string;
  cpu_pct: number;
  mem_mb: number;
}

interface NetworkIface {
  name: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_rate?: number;
  tx_rate?: number;
}

interface SiteSummary {
  total: number;
  active: number;
}

interface SslCountdown {
  domain: string;
  days_left: number;
  severity: string;
  // Present (non-null) when this row is a Docker Compose stack's certificate
  // rather than a site's - same convention as the certificates page.
  stack_id?: string | null;
}

interface TopIssue {
  title: string;
  severity: string;
  type: string;
  since: string;
}

interface Recommendation {
  severity: string;
  message: string;
  action: string;
}

// Maps a recommendation's `action` (emitted by GET /api/dashboard/intelligence)
// to the page that resolves it, so dashboard rows become drill-in links (#67).
const REC_ACTION_ROUTES: Record<string, string> = {
  backup: "/backup-orchestrator",
  security: "/security",
  diagnostics: "/security?tab=diagnostics",
  incidents: "/monitoring?tab=statuspage",
  ssl: "/monitoring?tab=certificates",
  alerts: "/monitoring?tab=alerts",
};

interface Intelligence {
  health_score: number;
  grade: string;
  firing_alerts: number;
  acknowledged_alerts: number;
  open_incidents: number;
  stale_backups: number;
  scan_critical: number;
  scan_warnings: number;
  ssl_countdowns: SslCountdown[];
  top_issues: TopIssue[];
  recommendations: Recommendation[];
}

interface MetricPoint {
  cpu: number;
  mem: number;
  disk: number;
  time: string;
}

function Sparkline({ data, color, height = 60 }: { data: number[]; color: string; height?: number }) {
  if (data.length < 2) return null;
  const max = Math.max(...data, 1);
  const width = 300;
  const points = data.map((v, i) => {
    const x = (i / (data.length - 1)) * width;
    const y = height - (v / max) * (height - 4) - 2;
    return `${x},${y}`;
  }).join(" ");

  const fillPoints = `0,${height} ${points} ${width},${height}`;

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="w-full" preserveAspectRatio="none" aria-hidden="true">
      <polygon points={fillPoints} fill={color} opacity="0.16" />
      <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

function CountUp({ value }: { value: number }) {
  const displayed = useCountUp(value);
  return <>{displayed.toFixed(0)}</>;
}

function barColor(pct: number, type: "cpu" | "mem" | "disk" = "cpu"): string {
  if (type === "disk") {
    if (pct < 80) return "bg-rust-500";
    if (pct <= 90) return "bg-warn-500";
    return "bg-danger-500";
  }
  // CPU and Memory
  if (pct < 70) return "bg-rust-500";
  if (pct <= 90) return "bg-warn-500";
  return "bg-danger-500";
}

function pctColor(pct: number): string {
  if (pct < 60) return "text-dark-50";
  if (pct < 80) return "text-warn-400";
  return "text-danger-400";
}

function tempColor(temp: number): string {
  if (temp < 60) return "text-rust-400";
  if (temp < 80) return "text-warn-400";
  return "text-danger-400";
}

// Shared visual vocabulary for the page. Theme tokens only (dark-*, rust-*,
// accent-*, warn-*, danger-*) and the theme radius scale, so every layout and
// theme keeps restyling these through index.css.
const CARD = "bg-dark-800 rounded-xl border border-dark-600 px-5 py-4";
const CARD_HEAD = "flex items-center justify-between gap-3 pb-3 border-b border-dark-700";
const CARD_TITLE = "text-[15px] font-semibold text-dark-50";
const CARD_LINK = "text-[13px] text-rust-400 hover:text-rust-300 transition-colors";
const ROWS = "divide-y divide-dark-700";
const BTN = "h-11 px-3.5 rounded-lg border text-sm items-center gap-2 transition-colors";
const BTN_2ND = "font-medium bg-dark-800 border-dark-600 text-dark-100 hover:bg-dark-700";
const PILL = "min-h-9 items-center gap-2 px-3 rounded-full border text-xs";
const DIVIDER = "h-7 w-px bg-dark-600 hidden sm:block";
const TILE = "rounded-lg border px-3.5 py-3 flex flex-col gap-1 min-w-0 card-interactive";
const TILE_OK = "bg-dark-800 border-dark-600";
const TILE_WARN = "bg-warn-500/5 border-warn-500/30";
const TILE_BAD = "bg-danger-500/5 border-danger-500/30";
const TILE_LABEL = "font-mono text-[10px] text-dark-300 uppercase tracking-widest";
const TILE_VALUE = "text-[17px] font-bold";
const TH = "text-xs font-medium text-dark-400 px-3 first:pl-0 last:pr-0 py-2 border-b border-dark-600";
const TD = "px-3 first:pl-0 last:pr-0 py-2.5";

export default function Dashboard() {
  // Which machine this page is describing. Every REST read below carries the
  // selection in `X-Server-Id` (attached by the fetch wrapper in `api.ts`); the
  // live socket cannot carry it at all, which is why the socket is gated on
  // `isLocal` further down.
  const { isLocal, loading: serversLoading, activeServer, activeServerId } = useServer();

  // Almost everything this page reads is admin-only, and this page is where
  // every account lands after signing in. Without the role it asked the
  // whole system surface as anybody, and a non-admin's first screen was the
  // refusal: `/system/info` is admin-gated, its catch below surfaced the API's
  // own words, and the poll re-issued it every 5s - so a client saw a red
  // "Admin access required" over a heading stuck on "Loading...", which is
  // indistinguishable from having no access to their own site. Reported that
  // way on #51, twice, by an operator who was testing a client account.
  const { user } = useAuth();
  const isAdmin = user?.role === "admin";

  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [sites, setSites] = useState<SiteSummary>({ total: 0, active: 0 });
  const [dbCount, setDbCount] = useState(0);
  const [processes, setProcesses] = useState<Process[]>([]);
  const [network, setNetwork] = useState<NetworkIface[]>([]);
  const [error, setError] = useState("");
  const [intel, setIntel] = useState<Intelligence | null>(null);
  const [appCount, setAppCount] = useState(0);
  const [updateCount, setUpdateCount] = useState(0);
  const [rebootRequired, setRebootRequired] = useState(false);
  const [dismissed, setDismissed] = useState(() => localStorage.getItem("dp-onboarding-dismissed") === "1");
  const [onboardingCollapsed, setOnboardingCollapsed] = useState(() => localStorage.getItem('dp-onboarding-collapsed') === '1');
  const [metricsHistory, setMetricsHistory] = useState<MetricPoint[]>([]);
  const [twoFaEnabled, setTwoFaEnabled] = useState(false);
  const [backupSetup, setBackupSetup] = useState<{ has_schedule: boolean; has_backup: boolean }>({ has_schedule: false, has_backup: false });
  const [sitesList, setSitesList] = useState<SiteDetail[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [onCallSchedules, setOnCallSchedules] = useState<{ schedule_id: string; schedule_name: string }[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Feature #1: Docker container overview
  const [dockerInfo, setDockerInfo] = useState<{ total: number; running: number; stopped: number } | null>(null);
  // Feature #2: Recent activity feed
  const [recentActivity, setRecentActivity] = useState<ActivityItem[]>([]);
  // GET /api/dashboard/timeline - unified deploy/backup/incident/alert/security
  // feed, tenant-scoped server-side; had zero frontend caller until now.
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  // GET /api/dashboard/fleet - admin-only cross-server health; same gap.
  const [fleetOverview, setFleetOverview] = useState<FleetOverview | null>(null);
  // Feature #6: Bandwidth usage summary
  const [bandwidthTotal, setBandwidthTotal] = useState({ rx: 0, tx: 0 });
  // Feature #8: Docker image disk usage
  const [dockerDiskUsage, setDockerDiskUsage] = useState<string | null>(null);
  // Feature #9: Mail queue widget
  const [mailQueue, setMailQueue] = useState<number | null>(null);
  // Feature #4: Quick server action messages
  const [actionMessage, setActionMessage] = useState<{ text: string; type: string } | null>(null);
  const [confirmAction, setConfirmAction] = useState<string | null>(null);
  // Feature #3: Disk I/O metrics
  const [diskIo, setDiskIo] = useState<{ read_bytes_sec: number; write_bytes_sec: number } | null>(null);
  // Feature #6: Customizable dashboard layout
  const [widgetConfig, setWidgetConfig] = useState<Record<string, boolean>>(() => {
    try { return JSON.parse(localStorage.getItem('dp-dashboard-widgets') || '{}'); } catch { return {}; }
  });
  const [showWidgetConfig, setShowWidgetConfig] = useState(false);
  // Feature #12: Custom dashboard widgets (Quick Links / Bookmarks)
  const [bookmarks, setBookmarks] = useState<{ label: string; url: string }[]>(() => {
    try { return JSON.parse(localStorage.getItem('dp-dashboard-bookmarks') || '[]'); } catch { return []; }
  });
  const [showAddBookmark, setShowAddBookmark] = useState(false);
  const [bmLabel, setBmLabel] = useState("");
  const [bmUrl, setBmUrl] = useState("");
  // Update notification
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);

  const isVisible = (widget: string) => widgetConfig[widget] !== false; // default visible
  const toggleWidget = (widget: string) => {
    const next = { ...widgetConfig, [widget]: !isVisible(widget) };
    setWidgetConfig(next);
    localStorage.setItem('dp-dashboard-widgets', JSON.stringify(next));
  };

  const dismissOnboarding = useCallback(() => {
    setDismissed(true);
    localStorage.setItem("dp-onboarding-dismissed", "1");
  }, []);

  // Fetch endpoints NOT covered by WebSocket (slow-changing data)
  const fetchSlowData = useCallback(() => {
    api
      .get<SiteDetail[]>("/sites")
      .then((list) => {
        setSitesList(list);
        setSites({
          total: list.length,
          active: list.filter((s) => s.status === "active" && s.enabled !== false).length,
        });
      })
      .catch(() => setError("Failed to load sites. Please try again."));
    api
      .get<{ id: string }[]>("/databases")
      .then((list) => setDbCount(list.length))
      .catch(() => setError("Failed to load databases. Please try again."));
    api
      .get<Intelligence>("/dashboard/intelligence")
      .then(setIntel)
      .catch(() => setError("Failed to load dashboard intelligence"));
    // Any authenticated user - this is the one on-call surface that isn't
    // admin-gated, built specifically so a non-admin operator can self-check
    // without seeing the schedule layout.
    api
      .get<{ schedule_id: string; schedule_name: string }[]>("/on-call/whoami")
      .then(setOnCallSchedules)
      .catch(() => {});
    // Every handler in `routes/docker_apps.rs` calls `require_admin`, this one
    // included - containers on the box belong to nobody in particular, so there is
    // no tenant view of them to ask for. Same reasoning as the reads below.
    if (isAdmin) {
      api
        .get<{ container_id: string }[]>("/apps")
        .then((list) => setAppCount(list.length))
        .catch(() => {});
    }
    // Admin-gated in `routes/system.rs`. Asking as anybody else produced the
    // page's second error banner, beside the one from `/system/info`.
    if (isAdmin) {
      api
        .get<{ count: number; security: number; reboot_required: boolean }>("/system/updates/count")
        .then((d) => { setUpdateCount(d.count); setRebootRequired(d.reboot_required); })
        .catch(() => setError("Failed to load system update status"));
    }
    api
      .get<{ points: MetricPoint[] }>("/dashboard/metrics-history")
      .then((d) => setMetricsHistory(d.points || []))
      .catch(() => {});
    api
      .get<{ enabled: boolean }>("/auth/2fa/status")
      .then((d) => setTwoFaEnabled(d.enabled))
      .catch(() => {});
    api
      .get<{ has_schedule: boolean; has_backup: boolean }>("/backup-setup-status")
      .then(setBackupSetup)
      .catch(() => {});
    // Feature #1: Docker container overview. Admin-gated in the backend since
    // v2.77.0 - it asks the agent for the same `/apps` the list above does.
    if (isAdmin) {
      api
        .get<{ total: number; running: number; stopped: number }>("/dashboard/docker")
        .then(setDockerInfo)
        .catch(() => {});
    }
    // Feature #2: Recent activity feed
    // Admin-gated in the backend; asking as anybody else is a refusal
    // every 5s that this page then swallows (activity feed).
    if (isAdmin) {
      api
        .get<ActivityItem[]>("/activity?limit=5")
        .then(setRecentActivity)
        .catch(() => {});
    }
    // Unified timeline - scoped to the caller's own resources server-side
    // (AuthUser, not AdminUser), so safe to fetch for every role.
    api
      .get<TimelineEvent[]>("/dashboard/timeline")
      .then(setTimeline)
      .catch(() => {});
    // Fleet-wide health overview - admin only in the backend (AdminUser).
    if (isAdmin) {
      api
        .get<FleetOverview>("/dashboard/fleet")
        .then(setFleetOverview)
        .catch(() => {});
    }
    // Feature #8: Docker image disk usage - `docker_apps` again, so admin only.
    if (isAdmin) {
      api
        .get<DockerImage[] | DockerImagesResponse>("/apps/images")
        .then((d) => {
          const images: DockerImage[] = Array.isArray(d) ? d : ((d as DockerImagesResponse).images || []);
          const totalMb = images.reduce((sum: number, img: DockerImage) => {
            const size = img.size || img.Size || "0";
            if (typeof size === "number") return sum + size / (1024 * 1024);
            const match = String(size).match(/([\d.]+)\s*(GB|MB|KB)/i);
            if (match) {
              const val = parseFloat(match[1]);
              if (match[2].toUpperCase() === "GB") return sum + val * 1024;
              if (match[2].toUpperCase() === "MB") return sum + val;
              return sum + val / 1024;
            }
            return sum;
          }, 0);
          setDockerDiskUsage(totalMb > 1024 ? `${(totalMb / 1024).toFixed(1)} GB` : `${totalMb.toFixed(0)} MB`);
        })
        .catch(() => {});
    }
    // Feature #3: Disk I/O metrics (endpoint takes ~1s due to sampling)
    // Admin-gated in `routes/system.rs` like the rest of that module.
    if (isAdmin) {
      api
        .get<DiskIoResponse>("/system/disk-io")
        .then(setDiskIo)
        .catch(() => {});
    }
    // Feature #9: Mail queue count
    // Admin-gated in the backend; asking as anybody else is a refusal
    // every 5s that this page then swallows (mail queue).
    if (isAdmin) {
      api
        .get<MailQueueResponse>("/mail/queue")
        .then((d) => {
          const count = d.count ?? (Array.isArray(d.queue) ? d.queue.length : 0);
          setMailQueue(count);
        })
        .catch(() => {});
    }
  }, [isAdmin]);

  // Update check. Refetched every time the tab regains focus, because the row
  // behind this banner is cleared server-side - on the first boot after an
  // upgrade, and on every poll that finds nothing newer. Without a refetch a
  // dashboard left open kept advertising an update that no longer existed until
  // someone reloaded the page. Focus rather than an interval: a dashboard
  // nobody is looking at costs nothing, and the banner is only wrong to a
  // person who is looking at it.
  useEffect(() => {
    const loadUpdateInfo = () => {
      // Admin-gated in the backend; asking as anybody else is a refusal this
      // page then swallows (update status).
      if (isAdmin) {
        api
          .get<UpdateInfo>("/telemetry/update-status")
          .then(setUpdateInfo)
          .catch(() => {});
      }
    };
    loadUpdateInfo();
    window.addEventListener("focus", loadUpdateInfo);
    return () => window.removeEventListener("focus", loadUpdateInfo);
  }, []);

  // Fetch real-time system endpoints (only needed when WS is disconnected)
  const fetchRealtimeData = useCallback(() => {
    // Every read here is admin-gated in `routes/system.rs`, so for anybody else
    // this whole block is three refusals per tick and nothing to show. Not
    // asking is the fix; swallowing the error would leave the tiles pretending
    // to load for ever.
    if (!isAdmin) return;
    api
      .get<SystemInfo>("/system/info")
      .then(setSystem)
      // Deliberately NOT the API's own message. This is the only catch on the
      // page that forwarded it, and what it forwarded was an authorization
      // refusal aimed at the operator rather than the reader.
      .catch(() => setError("Failed to load system info"));
    api
      .get<Process[]>("/system/processes")
      .then(setProcesses)
      .catch(() => {});
    api
      .get<NetworkIface[]>("/system/network")
      .then(setNetwork)
      .catch(() => {});
  }, [isAdmin]);

  // WebSocket connection for live metrics - PANEL HOST ONLY, deliberately.
  //
  // The browser's WebSocket API cannot set request headers, so this socket
  // cannot carry the selected server the way every REST read on this page does
  // (the fetch wrapper in `api.ts` is the only thing in the client that sends
  // that header). The backend's scope extractor therefore resolves this socket
  // to the LOCAL agent no matter what the picker says - so opening it while a
  // member is selected streams the PANEL's numbers into `setSystem`,
  // `setProcesses` and `setNetwork`, the same state the server-scoped poll below
  // writes. The two would alternate on the 3s reconnect timer and the tiles
  // would silently change machine.
  //
  // The fix is not to proxy the socket: a streaming proxy must not land before
  // the terminal ticket binds its own domain (see the J9 tripwire), and it is
  // not needed here anyway. The poll below already reads the selected host
  // every 5s through the header, so leaving the socket shut makes a member's
  // tiles CORRECT, not merely honest.
  useEffect(() => {
    if (serversLoading || !isLocal) {
      // Not an error state - the live-tile poll below owns this case, and it is
      // guarded on `wsConnected`, so the flag must be cleared here: the teardown
      // deliberately nulls `onclose` before closing, so nothing else resets it.
      setWsConnected(false);
      return;
    }

    function connect() {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
        reconnectTimer.current = null;
      }
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${protocol}//${window.location.host}/api/ws/metrics`);

      ws.onopen = () => {
        setWsConnected(true);
      };

      ws.onclose = () => {
        setWsConnected(false);
        wsRef.current = null;
        // Reconnect after 3 seconds
        reconnectTimer.current = setTimeout(connect, 3000);
      };

      ws.onerror = () => {
        setWsConnected(false);
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          if (data.type === "metrics") {
            if (data.system) setSystem(data.system);
            if (data.processes) setProcesses(data.processes);
            if (data.network) {
              setNetwork(data.network);
              // Feature #6: Track cumulative bandwidth
              const rx = (data.network as NetworkIface[]).reduce((sum, iface) => sum + (iface.rx_bytes || 0), 0);
              const tx = (data.network as NetworkIface[]).reduce((sum, iface) => sum + (iface.tx_bytes || 0), 0);
              setBandwidthTotal({ rx, tx });
            }
          }
        } catch {
          // malformed WS frame - ignore
        }
      };

      wsRef.current = ws;
    }

    connect();

    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current);
      const ws = wsRef.current;
      if (ws) {
        // Prevent reconnect on intentional close - null handlers before close
        ws.onclose = null;
        ws.onerror = null;
        ws.onmessage = null;
        wsRef.current = null;
        ws.close();
      }
      // Nulling `onclose` above means the socket's own handler will NOT run, so
      // this is the only place the flag gets cleared on a server switch. Without
      // it, switching from the panel host to a member leaves `wsConnected` true:
      // the live-tile poll below is guarded on it, so it would never run and the
      // tiles would freeze on the panel's last values while the badge read "Live".
      setWsConnected(false);
    };
  }, [isLocal, serversLoading]);

  // Slow data - always 15s, whatever the socket is doing.
  //
  // These two cadences used to share one timer, so the interval that exists to
  // make the LIVE tiles keep up (5s, whenever the socket is not supplying them)
  // also dragged sites, databases, containers, activity and the mail queue along
  // with it. That was invisible while the socket was almost always up. It stops
  // being invisible once the socket is deliberately not opened for a remote
  // server: slow data would have polled three times as often, through the
  // panel-to-agent hop, for values that change on the order of minutes.
  //
  // `activeServerId` is a dependency because every read resolves the host at
  // call time from the stored selection - without it a server switch would
  // leave the previous machine's numbers on screen until the next tick.
  useEffect(() => {
    fetchSlowData();
    const slow = setInterval(fetchSlowData, 15000);
    return () => clearInterval(slow);
  }, [activeServerId, fetchSlowData]);

  // Live tiles - 5s, and only when the socket is not already supplying them.
  useEffect(() => {
    if (wsConnected) return;
    fetchRealtimeData();
    const fast = setInterval(fetchRealtimeData, 5000);
    return () => clearInterval(fast);
  }, [wsConnected, activeServerId, fetchRealtimeData]);

  // Feature #7: Disk full prediction based on historical usage trend
  const diskForecast = useMemo(() => {
    if (!metricsHistory || metricsHistory.length < 10) return null;
    const points = metricsHistory;
    const first = points[0];
    const last = points[points.length - 1];
    // Estimate hours between first and last point (each point ~15min apart)
    const hours = (points.length - 1) * 0.25;
    if (hours < 1) return null;
    const firstDisk = first.disk;
    const lastDisk = last.disk;
    const ratePerHour = (lastDisk - firstDisk) / hours;
    if (ratePerHour <= 0) return null; // Disk not growing
    const remaining = 100 - lastDisk;
    const hoursLeft = remaining / ratePerHour;
    const daysLeft = Math.floor(hoursLeft / 24);
    return daysLeft > 365 ? null : daysLeft; // Only show if meaningful
  }, [metricsHistory]);

  // Feature #10: Visual health indicator.
  //
  // The destination follows the REASON the pill is showing, which it did not
  // used to: every state linked to a bare `/monitoring`, and that resolves to the
  // Monitors tab. So "System Issues Detected" - which is raised by firing alerts -
  // took you to a list of uptime monitors, and on an install with no monitors
  // configured that is an empty screen while alerts are firing. This page already
  // knew the right answer: `REC_ACTION_ROUTES.alerts` is `/monitoring?tab=alerts`
  // and three other links on this same screen use it. Monitoring.tsx's own
  // comment names `/monitoring?tab=alerts from the dashboard` as the contract.
  const overallStatus = useMemo(() => {
    const alertCount = intel?.firing_alerts ?? 0;
    const healthScore = intel?.health_score ?? 100;
    if (alertCount > 0)
      return {
        label: "System Issues Detected",
        to: REC_ACTION_ROUTES.alerts,
        title: `${alertCount} firing alert${alertCount === 1 ? "" : "s"} - open the Alerts tab`,
        color: "bg-danger-500/10 border-danger-500/20 text-danger-400",
        dot: "bg-danger-400",
      };
    // No alert is firing, so the score is what is low. That is a property of the
    // server rather than of a monitor, and the Monitors tab is where the server's
    // own checks live - the default destination is right for this branch only.
    if (healthScore < 50)
      return {
        label: "System Issues Detected",
        to: "/monitoring",
        title: `Health score ${healthScore} - open monitoring`,
        color: "bg-danger-500/10 border-danger-500/20 text-danger-400",
        dot: "bg-danger-400",
      };
    if (healthScore < 80)
      return {
        label: "Degraded Performance",
        to: "/monitoring",
        title: `Health score ${healthScore} - open monitoring`,
        color: "bg-warn-500/10 border-warn-500/20 text-warn-400",
        dot: "bg-warn-500",
      };
    return {
      label: "All Systems Operational",
      to: "/monitoring",
      title: "View monitoring & system status",
      color: "bg-rust-500/10 border-rust-500/20 text-rust-400",
      dot: "bg-rust-500",
    };
  }, [intel]);

  // Feature #6: Also update bandwidth when network changes via polling
  useEffect(() => {
    if (network.length > 0) {
      const rx = network.reduce((sum, iface) => sum + (iface.rx_bytes || 0), 0);
      const tx = network.reduce((sum, iface) => sum + (iface.tx_bytes || 0), 0);
      setBandwidthTotal({ rx, tx });
    }
  }, [network]);

  return (
    <div className="p-4 sm:p-6 lg:p-8 animate-fade-up">
      <div className="page-header">
        <div className="flex flex-col gap-1.5 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-2xl sm:text-[28px] leading-tight font-bold tracking-tight text-dark-50">Dashboard</h1>
            <span
              className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md border border-dark-600 bg-dark-800"
              title={
                wsConnected
                  ? "Receiving live metrics via WebSocket"
                  : isLocal
                    ? "Polling metrics via HTTP"
                    : `Polling ${activeServer?.name ?? "this server"} over HTTP every 5s - the live socket reads the panel host only, so it is not used for a remote server`
              }
            >
              <span className={`w-1.5 h-1.5 rounded-full ${wsConnected ? "bg-rust-500 animate-pulse" : "bg-dark-400"}`} />
              <span className="text-[11px] text-dark-300 font-mono">{wsConnected ? "Live" : "Polling"}</span>
            </span>
          </div>
          {/* `system` is an admin-only read, so for anybody else it never
              arrives - and "Loading..." that never resolves is the visible
              half of the same defect as the refusal banner. Say what this
              account is instead. */}
          <p className="text-[13px] text-dark-300 font-mono break-words">
            {system?.hostname || (isAdmin ? "Loading..." : user?.email)}
          </p>
        </div>
        <div className="flex items-center gap-2.5 flex-wrap">
          {intel && isVisible("health_banner") && (
            <Link to={overallStatus.to} title={overallStatus.title} className={`hidden sm:flex ${PILL} font-semibold hover:opacity-80 transition-opacity ${overallStatus.color}`}>
              <span className={`w-[7px] h-[7px] rounded-full ${overallStatus.dot} ${overallStatus.dot === "bg-rust-500" ? "animate-pulse" : ""}`} />
              {overallStatus.label}
            </Link>
          )}
          {intel && isVisible("health_banner") && (
            <div className={DIVIDER} />
          )}
          {onCallSchedules.length > 0 && (
            isAdmin ? (
              <Link
                to="/alerts"
                title={`You're on call for: ${onCallSchedules.map(s => s.schedule_name).join(", ")}`}
                className={`hidden sm:flex ${PILL} font-medium hover:opacity-80 transition-opacity bg-accent-500/10 border-accent-500/20 text-accent-400`}
              >
                <span className="w-[7px] h-[7px] rounded-full bg-accent-500" />
                On call: {onCallSchedules.map(s => s.schedule_name).join(", ")}
              </Link>
            ) : (
              // Non-admins have no page to land on - Alerts.tsx's OnCallTab is
              // admin-only - so this is informational only, not a link.
              <span
                title="You're currently the on-call responder for this schedule"
                className={`hidden sm:flex ${PILL} font-medium bg-accent-500/10 border-accent-500/20 text-accent-400`}
              >
                <span className="w-[7px] h-[7px] rounded-full bg-accent-500" />
                On call: {onCallSchedules.map(s => s.schedule_name).join(", ")}
              </span>
            )
          )}
          {onCallSchedules.length > 0 && (
            <div className={DIVIDER} />
          )}
          <button onClick={() => setShowWidgetConfig(!showWidgetConfig)}
            className={`inline-flex ${BTN} ${BTN_2ND}`}>
            {showWidgetConfig ? "Done" : "Customize"}
          </button>
          <div className={DIVIDER} />
          {/* The same dead end as "Add Site" below, one link earlier and missed
              when that one was fixed: `Apps.tsx` bounces any non-admin straight
              back here, and every handler in `routes/docker_apps.rs` requires
              admin. Docker Apps is an operator capability, so say so by not
              offering it. */}
          {isAdmin && (
            <Link to="/apps" className={`hidden sm:flex ${BTN} ${BTN_2ND}`}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg>
              Deploy App
            </Link>
          )}
          {/* A `client` cannot bring a new domain into service by any route, so
              offering it the shortcut named for exactly that is a dead end -
              it lands on the one refusal the role is defined by. */}
          {user?.role !== "client" && (
            <Link to="/sites" className={`flex ${BTN} font-semibold bg-rust-500 border-rust-500 text-white hover:bg-rust-600`}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m7.5-7.5h-15" /></svg>
              Add Site
            </Link>
          )}
          {isAdmin && (
            <Link to={REC_ACTION_ROUTES.diagnostics} className={`hidden sm:flex ${BTN} ${BTN_2ND}`}>
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75a4.5 4.5 0 01-4.884 4.484c-1.076-.091-2.264.071-2.95.904l-7.152 8.684a2.548 2.548 0 11-3.586-3.586l8.684-7.152c.833-.686.995-1.874.904-2.95a4.5 4.5 0 016.336-4.486l-3.276 3.276a3.004 3.004 0 002.25 2.25l3.276-3.276c.256.565.398 1.192.398 1.852z" /></svg>
              Diagnostics
            </Link>
          )}
          {/* Feature #4: Quick Server Actions - hidden on mobile.
              Shown only once there is something to restart. On a brand-new box
              these sat next to "Add Site" as the first thing an operator met,
              three server-level destructive verbs offered before a single site
              existed. Restart Nginx / Restart PHP remain available any time from
              Diagnostics (they post the same restart-service fix); Reboot has no
              other home, so it also appears whenever the system reports one is
              actually required. */}
          {isAdmin && (sites.total > 0 || appCount > 0) && (
            <>
              <div className={DIVIDER} />
              <button onClick={() => setConfirmAction("nginx")} className={`hidden sm:inline-flex ${BTN} ${BTN_2ND}`}>
                Restart Nginx
              </button>
              <button onClick={() => setConfirmAction("php")} className={`hidden sm:inline-flex ${BTN} ${BTN_2ND}`}>
                Restart PHP
              </button>
            </>
          )}
          {isAdmin && (rebootRequired || sites.total > 0 || appCount > 0) && (
            <button onClick={() => setConfirmAction("reboot")} className={`hidden sm:inline-flex ${BTN} font-semibold bg-danger-500/10 border-danger-500/30 text-danger-400 hover:bg-danger-500/20`}>
              {rebootRequired ? "Reboot required" : "Reboot"}
            </button>
          )}
        </div>
      </div>

      {/* Feature #6: Widget customization panel */}
      {showWidgetConfig && (
        <div className="bg-dark-800 rounded-xl border border-dark-600 px-5 py-[18px] mb-6">
          <h3 className="text-[11px] font-semibold text-dark-300 uppercase font-mono tracking-widest mb-3.5">Dashboard Widgets</h3>
          <div className="grid grid-cols-1 min-[420px]:grid-cols-2 md:grid-cols-4 gap-x-4 gap-y-1">
            {/* `hostOnly` marks a widget fed by an admin-only read. Offering a
                client a checkbox for a panel that can never draw is the same
                empty promise as a menu entry that refuses - eight of these
                fourteen were exactly that. */}
            {[
              { id: "metrics", label: "CPU / Memory / Disk", hostOnly: true },
              { id: "disk_io", label: "Disk I/O", hostOnly: true },
              { id: "charts", label: "Historical Charts", hostOnly: true },
              { id: "status_bar", label: "Status Bar" },
              { id: "health_banner", label: "Health Indicator" },
              { id: "sites_grid", label: "Sites Grid" },
              { id: "activity", label: "Recent Activity", hostOnly: true },
              { id: "timeline", label: "Timeline" },
              { id: "fleet", label: "Fleet Health", hostOnly: true },
              { id: "issues", label: "Active Issues" },
              { id: "ssl_countdown", label: "SSL Countdown" },
              { id: "network", label: "Network I/O", hostOnly: true },
              { id: "processes", label: "Top Processes", hostOnly: true },
              { id: "system_info", label: "System Info", hostOnly: true },
              { id: "onboarding", label: "Getting Started", hostOnly: true },
              { id: "bookmarks", label: "Quick Links" },
            ].filter(w => isAdmin || !w.hostOnly).map(w => (
              <label key={w.id} className="flex items-center gap-2.5 min-h-9 text-[13px] text-dark-100 cursor-pointer hover:text-dark-50">
                <input type="checkbox" checked={isVisible(w.id)} onChange={() => toggleWidget(w.id)}
                  className="w-4 h-4 accent-rust-500 shrink-0" />
                {w.label}
              </label>
            ))}
          </div>
          <button onClick={() => { setWidgetConfig({}); localStorage.removeItem('dp-dashboard-widgets'); }}
            className="mt-2.5 py-1.5 text-[13px] text-rust-400 hover:text-rust-300">Reset to defaults</button>
        </div>
      )}

      {/* Health banner moved to page header */}

      {/* Update available banner */}
      {updateInfo?.update_available && updateInfo.update_available_version && (
        <div className="rounded-xl border border-rust-500/30 bg-rust-500/10 px-4 py-3 mb-6 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 flex-[1_1_260px] min-w-0">
            <svg className="w-[18px] h-[18px] text-rust-400 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}><path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            <span className="text-sm text-dark-100">
              <strong>CyberHunter - Panel v{updateInfo.update_available_version}</strong> is available
              <span className="text-dark-400 ml-1">(current: v{updateInfo.current_version})</span>
            </span>
          </div>
          <Link to="/telemetry?tab=updates" className="inline-flex items-center min-h-9 px-3.5 bg-rust-500 hover:bg-rust-600 text-white rounded-lg text-[13px] font-semibold transition-colors whitespace-nowrap">
            View Update
          </Link>
        </div>
      )}

      {/* Feature #4: Action confirmation bar */}
      {confirmAction && (
        <div className={`rounded-xl border px-4 py-3 mb-6 flex flex-wrap items-center justify-between gap-3 ${
          confirmAction === "reboot" ? "border-danger-500/40 bg-danger-500/5" : "border-warn-500/40 bg-warn-500/5"
        }`}>
          <span className={`flex-[1_1_260px] text-sm ${confirmAction === "reboot" ? "text-danger-400" : "text-warn-400"}`}>
            {confirmAction === "nginx" ? "Restart Nginx? This will briefly interrupt web traffic." :
             confirmAction === "php" ? "Restart PHP-FPM? Active requests may be interrupted." :
             "Reboot server? All services will be temporarily unavailable."}
          </span>
          <div className="flex items-center gap-2 shrink-0">
            <button onClick={async () => {
              const action = confirmAction;
              setConfirmAction(null);
              try {
                if (action === "reboot") {
                  await api.post("/system/reboot");
                  setActionMessage({ text: "Server rebooting...", type: "success" });
                  setTimeout(() => setActionMessage(null), 5000);
                } else {
                  await api.post("/agent/diagnostics/fix", {
                    fix_id: action === "nginx" ? "restart-service:nginx" : "restart-service:php-fpm",
                  });
                  setActionMessage({ text: action === "nginx" ? "Nginx restarted" : "PHP-FPM restarted", type: "success" });
                  setTimeout(() => setActionMessage(null), 3000);
                }
              } catch (err) {
                // The agent authors a real sentence for these - nginx's own
                // "[emerg] invalid parameter" is what tells the operator which
                // line of which vhost to fix - and `error.rs::agent_error`
                // passes a 4xx through intact precisely so it survives. Bare
                // catching it here deleted the useful half and left "Failed to
                // restart Nginx", which is the #90/#91/#92 class all over again.
                const what = action === "reboot" ? "reboot the server" : `restart ${action === "nginx" ? "Nginx" : "PHP-FPM"}`;
                const why = err instanceof Error ? err.message : "";
                setActionMessage({ text: why ? `Could not ${what}: ${why}` : `Could not ${what}`, type: "error" });
                setTimeout(() => setActionMessage(null), 10000);
              }
            }} className="min-h-10 px-4 rounded-lg bg-danger-500 text-white text-xs font-bold uppercase tracking-wider hover:bg-danger-600 transition-colors">
              Confirm
            </button>
            <button onClick={() => setConfirmAction(null)} className="min-h-10 px-3.5 rounded-lg border border-dark-600 bg-transparent text-dark-200 text-xs font-bold uppercase tracking-wider hover:bg-dark-700 transition-colors">
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* Feature #4: Action message toast */}
      {actionMessage && (
        <div className={`w-fit max-w-full rounded-lg border px-3.5 py-2.5 mb-6 text-sm font-medium ${
          actionMessage.type === "success" ? "bg-rust-500/10 border-rust-500/20 text-rust-400" : "bg-danger-500/10 border-danger-500/20 text-danger-400"
        }`}>
          {actionMessage.text}
        </div>
      )}

      {error && (
        <div className="bg-danger-500/10 text-danger-400 text-sm px-4 py-3.5 rounded-xl border border-danger-500/30 mb-6">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 shrink-0 mt-0.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" />
            </svg>
            <div>
              <p className="font-medium">{error}</p>
              {error.includes("Agent offline") && (
                <p className="text-xs text-dark-300 mt-1 font-mono">
                  Run: <span className="text-dark-100">systemctl restart dockpanel-agent</span>
                </p>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Getting Started. Explicitly admin-only: it is titled "set up your server"
          and four of its five steps land on pages a client cannot open (/apps,
          /settings, /backup-orchestrator are all adminOnly). It used to be gated
          on `system` being loaded, which hid it from clients by accident - the
          right outcome for the wrong reason, and it broke the moment the body
          below stopped being keyed on `system`. */}
      {isAdmin && isVisible("onboarding") && !dismissed && system && (() => {
        // Every check must be able to come back FALSE. "Run diagnostics" used to
        // sit here with `check: () => true`, so a box where nothing had been done
        // still reported 1/5 - a checklist that counts a step nobody performed
        // teaches the operator not to trust the other four.
        const steps: OnboardingStep[] = [
          { id: "site", label: "Create your first site", description: "Set up a website with Nginx, PHP, or reverse proxy", link: "/sites", check: () => sites.total > 0 },
          // The prerequisite that gates everything else, and the one the list
          // never mentioned. A live certificate is the proof: HTTPS cannot be
          // issued until the domain actually resolves to this server.
          { id: "dns", label: "Point your domain here", description: "HTTPS is issued once your domain resolves to this server", link: "/sites", check: () => (intel?.ssl_countdowns.length ?? 0) > 0 },
          { id: "app", label: "Deploy a Docker app", description: "One-click deploy from the app catalogue", link: "/apps", check: () => appCount > 0 },
          { id: "2fa", label: "Enable 2FA", description: "Protect your panel with two-factor authentication", link: "/account", check: () => twoFaEnabled },
          { id: "backup", label: "Set up backups", description: "Schedule recurring backups or run one manually", link: "/backup-orchestrator", check: () => backupSetup.has_schedule || backupSetup.has_backup },
        ];
        const completed = steps.filter(s => s.check()).length;
        const isCollapsed = onboardingCollapsed || (completed >= 3 && localStorage.getItem('dp-onboarding-collapsed') !== '0');
        const toggleCollapse = () => {
          const next = !isCollapsed;
          setOnboardingCollapsed(next);
          localStorage.setItem('dp-onboarding-collapsed', next ? '1' : '0');
        };

        if (isCollapsed) {
          return (
            <div className="mb-6 bg-dark-800 border border-dark-600 rounded-xl px-5 py-2 animate-fade-up flex flex-wrap items-center justify-between gap-x-4 gap-y-1">
              <div className="flex items-center gap-3">
                <span className="text-[13px] font-semibold text-dark-100">Setup: {completed}/{steps.length} complete</span>
                <div className="flex gap-1.5">
                  {steps.map(step => (
                    <div key={step.id} className={`w-2 h-2 rounded-full ${step.check() ? "bg-rust-500" : "bg-dark-600"}`} />
                  ))}
                </div>
              </div>
              <div className="flex items-center gap-1 -mr-2.5">
                <button onClick={toggleCollapse} className="min-h-9 px-2.5 text-rust-400 hover:text-rust-300 text-[13px] font-medium">Expand</button>
                <button onClick={dismissOnboarding} className="min-h-9 px-2.5 text-dark-300 hover:text-dark-200 text-[13px]">Dismiss</button>
              </div>
            </div>
          );
        }

        return (
          <div className="mb-6 bg-dark-800 border border-dark-600 rounded-xl px-5 py-5 sm:px-[22px] animate-fade-up">
            <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-1 mb-1">
              <h3 className="text-lg font-bold text-dark-50 typewriter inline-block max-w-full">Welcome to CyberHunter - Panel</h3>
              <div className="flex items-center gap-1 -mr-2.5">
                <button onClick={toggleCollapse} className="min-h-9 px-2.5 text-dark-300 hover:text-dark-200 text-[13px] shrink-0">Collapse</button>
                <button onClick={dismissOnboarding} className="min-h-9 px-2.5 text-dark-300 hover:text-dark-200 text-[13px] shrink-0">Dismiss</button>
              </div>
            </div>
            <p className="text-[13px] text-dark-300 mb-4">Complete these steps to set up your server. <span className="text-rust-400 font-semibold">{completed}/{steps.length} done</span></p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3 stagger-children">
              {steps.map(step => (
                <Link
                  key={step.id}
                  to={step.link}
                  className={`rounded-lg border p-3.5 flex flex-col gap-2 transition-all hover-lift ${
                    step.check()
                      ? "border-rust-500/30 bg-dark-900/50 opacity-60"
                      : "border-dark-600 bg-dark-900/50 hover:border-rust-500/40"
                  }`}
                >
                  <div className="flex flex-col items-start gap-2">
                    {step.check() ? (
                      <div className="w-[26px] h-[26px] rounded-full bg-rust-500 flex items-center justify-center">
                        <svg className="w-3.5 h-3.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}><path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" /></svg>
                      </div>
                    ) : (
                      <div className="w-[26px] h-[26px] rounded-md bg-dark-700 flex items-center justify-center">
                        <span className="text-xs text-dark-200 font-mono font-semibold">{steps.indexOf(step) + 1}</span>
                      </div>
                    )}
                    <span className={`text-sm font-semibold ${step.check() ? "text-rust-400" : "text-dark-50"}`}>{step.label}</span>
                  </div>
                  <p className="text-xs text-dark-300 leading-relaxed">{step.description}</p>
                  {!step.check() && (
                    <span className="mt-auto text-xs text-rust-400 font-semibold">Start &rarr;</span>
                  )}
                </Link>
              ))}
            </div>
          </div>
        );
      })()}

      {/* `system` is an admin-only read - `fetchRealtimeData` returns early for
          anybody else and the metrics socket 403s them (ws_metrics.rs), so there
          are exactly two writers and both are gated. Keying the WHOLE body on it
          therefore meant a client sat in this skeleton for ever: not "six missing
          tiles" but six pulsing placeholders and nothing underneath, which is what
          the field report meant by "the Dashboard also have no stats".
          The skeleton is a LOADING state, so it belongs only to the account that
          has something loading. Everything below now renders for every role, and
          the host-level pieces carry their own `system &&` / `isAdmin &&`. */}
      {isAdmin && !system ? (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4" role="status" aria-live="polite">
          {[...Array(6)].map((_, i) => (
            <div key={i} className="bg-dark-800 rounded-xl border border-dark-600 p-[22px] animate-pulse">
              <div className="h-3 bg-dark-700 rounded-md w-20 mb-4" />
              <div className="h-10 bg-dark-700 rounded-md w-32" />
            </div>
          ))}
        </div>
      ) : (
        <>
          {/* System Information - host-level, so `system &&` rather than relying
              on the outer gate that used to supply it. */}
          {system && isVisible("system_info") && <div className="hidden sm:grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-px bg-dark-600 border border-dark-600 rounded-xl overflow-hidden mb-6">
            {[
              ["Hostname", system.hostname],
              ["OS", system.os],
              ["Kernel", system.kernel],
              ["Processor", system.cpu_model],
              ["Temperature", system.cpu_temp != null ? `${system.cpu_temp.toFixed(0)}°C` : "N/A"],
              ["Processes", system.process_count.toLocaleString()],
            ].map(([label, value]) => (
              <div key={label} className="bg-dark-800 px-4 py-3 flex flex-col gap-1 min-w-0 card-interactive">
                <span className={TILE_LABEL}>{label}</span>
                <span title={String(value)} className={`text-[13px] text-dark-50 font-medium truncate ${label === "Temperature" && system.cpu_temp != null ? tempColor(system.cpu_temp) : ""}`}>{value}</span>
              </div>
            ))}
          </div>}

          {/* Resource Metrics - 3 column. Host CPU/memory/disk: admin-only data. */}
          {system && isVisible("metrics") && <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6 stagger-children">
            {[
              { label: "CPU Usage", pct: system.cpu_usage, type: "cpu" as const, detail: `${system.cpu_count} cores${system.load_avg_1 !== undefined ? ` · Load ${system.load_avg_1?.toFixed(2)}` : ""}`,
                icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><rect x="6" y="6" width="12" height="12" rx="1" /><path d="M9 1v4m6-4v4M9 19v4m6-4v4M1 9h4m-4 6h4M19 9h4m-4 6h4" strokeLinecap="round" /></svg> },
              { label: "Memory", pct: system.mem_usage_pct, type: "mem" as const, detail: `${(system.mem_used_mb / 1024).toFixed(1)} / ${(system.mem_total_mb / 1024).toFixed(1)} GB${system.swap_total_mb > 0 ? ` · Swap ${(system.swap_used_mb / 1024).toFixed(1)}G` : ""}`,
                icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><rect x="3" y="4" width="18" height="16" rx="1" /><path d="M7 4v3m4-3v3m4-3v3M3 10h18" strokeLinecap="round" /></svg> },
              { label: "Disk", pct: system.disk_usage_pct, type: "disk" as const, detail: `${system.disk_used_gb.toFixed(0)} / ${system.disk_total_gb.toFixed(0)} GB · ${(system.disk_total_gb - system.disk_used_gb).toFixed(0)} GB free${dockerDiskUsage ? ` · Images: ${dockerDiskUsage}` : ""}`,
                icon: <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M21.75 17.25v-.228a4.5 4.5 0 0 0-.12-1.03l-2.268-9.64a3.375 3.375 0 0 0-3.285-2.602H7.923a3.375 3.375 0 0 0-3.285 2.602l-2.268 9.64a4.5 4.5 0 0 0-.12 1.03v.228m19.5 0a3 3 0 0 1-3 3H5.25a3 3 0 0 1-3-3m19.5 0a3 3 0 0 0-3-3H5.25a3 3 0 0 0-3 3m16.5 0h.008v.008h-.008v-.008Zm-3 0h.008v.008h-.008v-.008Z" /></svg> },
            ].map(({ label, pct, type, detail, icon }) => (
              <div key={label} className="border border-dark-600 bg-dark-800 rounded-xl p-5 sm:p-[22px] relative overflow-hidden shadow-lg shadow-black/10 elevation-1">
                <div className={`absolute inset-0 opacity-[0.03] ${pct < 60 ? "bg-dark-50" : pct < 85 ? "bg-warn-500" : "bg-danger-500"}`} />
                <div className="relative flex flex-col gap-3">
                  <div className="flex items-center gap-2 text-dark-300">
                    <span className="opacity-70">{icon}</span>
                    <span className="font-mono text-[11px] uppercase tracking-widest font-medium">{label}</span>
                  </div>
                  <div className={`text-[44px] leading-none font-semibold font-mono ${pctColor(pct)}`}>
                    <CountUp value={pct} /><span className="text-xl text-dark-300 ml-0.5">%</span>
                  </div>
                  <div className="h-2 bg-dark-700 rounded-full overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-500 ${barColor(pct, type)}`} style={{ width: `${Math.min(pct, 100)}%` }} />
                  </div>
                  <p className="text-xs text-dark-300">{detail}</p>
                  {/* Feature #7: Disk full forecast */}
                  {label === "Disk" && diskForecast !== null && diskForecast < 30 && (
                    <p className={`-mt-1.5 text-xs font-semibold ${diskForecast < 7 ? "text-danger-400" : "text-warn-400"}`}>
                      Disk full in ~{diskForecast}d at current rate
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>}

          {/* Disk I/O moved into stat bar below */}

          {/* Historical Charts */}
          {isVisible("charts") && metricsHistory.length >= 2 && (
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6 animate-fade-up">
              {[
                { label: "CPU", data: metricsHistory.map(p => p.cpu), color: "var(--color-rust-500)" },
                { label: "Memory", data: metricsHistory.map(p => p.mem), color: "var(--color-accent-500)" },
                { label: "Disk", data: metricsHistory.map(p => p.disk), color: "var(--color-warn-500)" },
              ].map(({ label, data, color }) => (
                <div key={label} className="border border-dark-600 bg-dark-800 rounded-xl px-[18px] py-4 elevation-1">
                  <div className="flex items-center justify-between gap-3 mb-2.5">
                    <span className="text-[13px] text-dark-200 font-semibold">{label} (24h)</span>
                    <span className="text-[13px] text-dark-50 font-mono">{data[data.length - 1]?.toFixed(1)}%</span>
                  </div>
                  <Sparkline data={data} color={color} height={48} />
                </div>
              ))}
            </div>
          )}

          {/* Status Bar - grid of stat cells */}
          {isVisible("status_bar") && <div className="grid grid-cols-2 sm:grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-2.5 mb-6 stagger-children">
            {/* The one host-derived cell in an otherwise tenant-safe grid, which is
                why this bar could not simply be shown or hidden as a whole. */}
            {system && (
              <div className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Uptime</span>
                <span className={`${TILE_VALUE} text-dark-50`}>{formatUptime(system.uptime_secs)}</span>
              </div>
            )}
            <Link to="/sites" className={`${TILE} ${TILE_OK}`}>
              <span className={TILE_LABEL}>Sites</span>
              <span className={`${TILE_VALUE} text-dark-50`}>{sites.total}{sites.active > 0 && <span className="text-rust-400 ml-1 text-xs font-medium">({sites.active} active)</span>}</span>
            </Link>
            <Link to="/databases" className={`${TILE} ${TILE_OK}`}>
              <span className={TILE_LABEL}>Databases</span>
              <span className={`${TILE_VALUE} text-dark-50`}>{dbCount}</span>
            </Link>
            {/* Feature #1: Docker container overview. Admin-only both ways: the
                count comes from an admin endpoint, and the cell links to a page
                that redirects anybody else. Rendered ungated it read "0/0 running"
                to a client - a number, not a blank, and a false one. */}
            {isAdmin && (
              <Link to="/apps" className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Docker</span>
                <span className={`${TILE_VALUE} text-dark-50`}>
                  {dockerInfo?.running ?? 0}<span className="text-xs text-dark-300 font-medium">/{dockerInfo?.total ?? 0}</span>
                  <span className="text-xs text-dark-400 font-medium ml-1">running</span>
                </span>
              </Link>
            )}
            {intel && <>
              {/* /security is adminOnly. For anybody else the score is now built
                  purely from their own alerts, certificates and backups (the host
                  diagnostics term is admin-only since v2.77.0), so /monitoring is
                  both reachable and the right explanation of the number. */}
              <Link to={isAdmin ? "/security?tab=diagnostics" : "/monitoring"} title={isAdmin ? "View system diagnostics that drive this score" : "View the alerts and certificates behind this score"} className={`${TILE} ${
                intel.health_score < 60 ? TILE_BAD : TILE_OK
              }`}>
                <span className={TILE_LABEL}>Health</span>
                <span className={`${TILE_VALUE} ${
                  intel.health_score >= 90 ? "text-rust-400" :
                  intel.health_score >= 75 ? "text-accent-400" :
                  intel.health_score >= 60 ? "text-warn-400" : "text-danger-400"
                }`}>{intel.health_score}/100 {intel.grade}</span>
              </Link>
              <Link to="/monitoring?tab=alerts" className={`${TILE} ${
                intel.firing_alerts > 0 ? TILE_BAD : TILE_OK
              }`}>
                <span className={TILE_LABEL}>Alerts</span>
                {intel.firing_alerts > 0
                  ? <span className={`${TILE_VALUE} text-danger-400`}>{intel.firing_alerts} firing</span>
                  : <span className={`${TILE_VALUE} text-rust-400`}>0</span>
                }
              </Link>
              <Link to="/monitoring?tab=certificates" className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>SSL</span>
                <span className={`${TILE_VALUE} text-dark-50`}>{intel.ssl_countdowns.length} certs</span>
              </Link>
              <Link to="/monitoring?tab=statuspage" className={`${TILE} ${
                intel.open_incidents > 0 ? TILE_BAD : TILE_OK
              }`}>
                <span className={TILE_LABEL}>Incidents</span>
                {intel.open_incidents > 0
                  ? <span className={`${TILE_VALUE} text-danger-400`}>{intel.open_incidents} open</span>
                  : <span className={`${TILE_VALUE} text-rust-400`}>0</span>
                }
              </Link>
              {/* /backup-orchestrator is adminOnly; a client's backups live per-site,
                  so send them where they can actually act on this count. */}
              <Link to={isAdmin ? "/backup-orchestrator" : "/sites"} className={`${TILE} ${
                intel.stale_backups > 0 ? TILE_WARN : TILE_OK
              }`}>
                <span className={TILE_LABEL}>Backups</span>
                {intel.stale_backups > 0
                  ? <span className={`${TILE_VALUE} text-warn-400`}>{intel.stale_backups} stale</span>
                  : <span className={`${TILE_VALUE} text-rust-400`}>fresh</span>
                }
              </Link>
            </>}
            {/* `updateCount` is only ever fetched for an admin, so for anybody else
                this cell asserted "up to date" about a machine it had not asked
                about. An unhidden blank is honest; an unhidden zero is a claim. */}
            {isAdmin && (
              <Link to="/updates" className={`${TILE} ${
                updateCount > 0 ? TILE_WARN : TILE_OK
              }`}>
                <span className={TILE_LABEL}>Updates</span>
                {updateCount > 0
                  ? <span className={`${TILE_VALUE} text-warn-400`}>{updateCount} available</span>
                  : <span className={`${TILE_VALUE} text-rust-400`}>up to date</span>
                }
              </Link>
            )}
            {/* Disk I/O */}
            {diskIo && isVisible("disk_io") && <>
              <div className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Disk Read</span>
                <span className={`${TILE_VALUE} text-dark-50 font-mono`}>{formatRate(diskIo.read_bytes_sec)}</span>
              </div>
              <div className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Disk Write</span>
                <span className={`${TILE_VALUE} text-dark-50 font-mono`}>{formatRate(diskIo.write_bytes_sec)}</span>
              </div>
            </>}
            {/* Feature #6: Bandwidth usage summary. Derived from `network`, which
                `fetchRealtimeData` only fetches for an admin - so this read
                "0 B / 0 B" to everybody else, host traffic reported as none. */}
            {isAdmin && (
              <div className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Bandwidth</span>
                <span className={`${TILE_VALUE} text-dark-50`}>
                  <span className="text-dark-400">{"\u2193"}</span>{formatSize(bandwidthTotal.rx)}
                  <span className="text-dark-400 ml-1">{"\u2191"}</span>{formatSize(bandwidthTotal.tx)}
                </span>
              </div>
            )}
            {/* Feature #9: Mail queue widget. `/mail/queue` is admin-gated, so the
                same false zero - and mail is admin-only end to end anyway. */}
            {isAdmin && (
              <div className={`${TILE} ${TILE_OK}`}>
                <span className={TILE_LABEL}>Mail Queue</span>
                <span className={`${TILE_VALUE} ${(mailQueue ?? 0) > 0 ? "text-warn-400" : "text-dark-50"}`}>
                  {mailQueue ?? 0} <span className="text-xs text-dark-400 font-medium">messages</span>
                </span>
              </div>
            )}
          </div>}

          {/* Reboot Required Warning */}
          {rebootRequired && (
            <div className="rounded-xl border border-warn-500/40 bg-warn-500/5 px-4 py-3.5 mb-6 flex flex-wrap items-center gap-3.5">
              <svg className="w-5 h-5 text-warn-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126ZM12 15.75h.007v.008H12v-.008Z" /></svg>
              <div className="flex-[1_1_260px] min-w-0">
                <p className="text-sm text-warn-400 font-bold">Reboot Required</p>
                <p className="text-[13px] text-dark-300 mt-0.5">Recent package updates (such as a new kernel version) require a reboot to be fully applied.</p>
              </div>
              <Link to="/updates" className="inline-flex items-center min-h-9 px-3.5 rounded-lg bg-warn-500/15 text-warn-400 text-[13px] font-semibold hover:bg-warn-500/25 transition-colors shrink-0">
                View Updates
              </Link>
            </div>
          )}

          {/* Fleet Health - cross-server overview for admins. GET /api/dashboard/fleet
              was fully built and hardened (v2.185.0/v2.188.0) but had zero frontend
              caller; a single-server install has nothing this adds over the rest of
              the page, so it only renders once there's an actual fleet to show. */}
          {/* Fleet Health and Sites share a row when both draw; auto-fit lets a
              lone card take the full width, and the wrapper vanishes when empty. */}
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] gap-4 items-start mb-6 empty:hidden">
          {isAdmin && isVisible("fleet") && fleetOverview && fleetOverview.servers.length > 1 && (
            <div className={CARD}>
              <div className={CARD_HEAD}>
                <h3 className={CARD_TITLE}>Fleet Health</h3>
                <Link to="/servers" className={CARD_LINK}>Manage</Link>
              </div>
              <div className={ROWS}>
                {fleetOverview.servers.map((s) => (
                  <Link key={s.id} to="/servers" className="-mx-2 px-2 py-2.5 flex flex-wrap items-center justify-between gap-x-3 gap-y-1 rounded-md hover:bg-dark-700/40 transition-colors">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <div className={`w-2 h-2 rounded-full shrink-0 ${s.status === "healthy" ? "bg-rust-500" : "bg-warn-500"}`} />
                      <span className="text-[13px] text-dark-50 font-mono truncate">{s.name}</span>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-dark-300 shrink-0">
                      {s.cpu_pct != null && <span>CPU {s.cpu_pct.toFixed(0)}%</span>}
                      {s.mem_pct != null && <span>Mem {s.mem_pct.toFixed(0)}%</span>}
                      <span>{s.sites} sites</span>
                      {s.firing_alerts > 0
                        ? <span className="text-danger-400 font-bold">{s.firing_alerts} firing</span>
                        : <span className="text-rust-400 font-semibold">0 firing</span>}
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Feature #5: Site Status Mini-Grid */}
          {isVisible("sites_grid") && sitesList.length > 0 && (
            <div className={CARD}>
              <div className={`${CARD_HEAD} mb-3`}>
                <h3 className={CARD_TITLE}>Sites</h3>
                <Link to="/sites" className={CARD_LINK}>Manage</Link>
              </div>
              <div className="grid grid-cols-[repeat(auto-fill,minmax(150px,1fr))] gap-2">
                {sitesList.slice(0, 12).map((s) => (
                  <Link key={s.id} to={`/sites/${s.id}`} className="min-h-10 px-3 rounded-lg border border-dark-600 bg-dark-900/50 flex items-center gap-2 min-w-0 hover:bg-dark-700/50 transition-colors">
                    <div
                      title={s.enabled === false ? "Disabled" : s.status}
                      className={`w-[7px] h-[7px] rounded-full shrink-0 ${
                        s.enabled === false ? "bg-warn-500" : s.status === "active" ? "bg-rust-500" : "bg-dark-500"
                      }`}
                    />
                    <span className="text-[13px] font-medium text-dark-100 truncate">{s.domain || s.id}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
          </div>

          {/* Recent Activity and Timeline share a row, same rule as above. */}
          <div className="grid grid-cols-[repeat(auto-fit,minmax(min(100%,340px),1fr))] gap-4 items-start mb-6 empty:hidden">
          {/* Feature #2: Recent Activity Feed */}
          {isVisible("activity") && recentActivity.length > 0 && (
            <div className={CARD}>
              <div className={CARD_HEAD}>
                <h3 className={CARD_TITLE}>Recent Activity</h3>
                <Link to="/logs?tab=audit" className={CARD_LINK}>View all</Link>
              </div>
              <div className={ROWS}>
                {recentActivity.map((a, i) => (
                  <div key={i} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className={`px-2 py-0.5 rounded-md font-mono text-[11px] font-medium shrink-0 ${
                        a.action?.includes("create") || a.action?.includes("deploy") ? "bg-rust-500/15 text-rust-400" :
                        a.action?.includes("delete") || a.action?.includes("remove") ? "bg-danger-500/15 text-danger-400" :
                        "bg-dark-700 text-dark-200"
                      }`}>{a.action}</span>
                      {a.target_name && <span className="text-dark-200 font-mono truncate">{a.target_name}</span>}
                    </div>
                    <span className="text-dark-400 text-xs shrink-0">{timeAgo(a.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Timeline - unified deploy/backup/incident/alert/security feed. Scoped
              server-side to the caller's own resources, so (unlike Recent Activity
              above) it renders for every role, not just admins. GET
              /api/dashboard/timeline was fully built and hardened but had zero
              frontend caller. */}
          {isVisible("timeline") && timeline.length > 0 && (
            <div className={CARD}>
              <div className={CARD_HEAD}>
                <h3 className={CARD_TITLE}>Timeline</h3>
              </div>
              <div className={ROWS}>
                {timeline.slice(0, 10).map((e, i) => (
                  <div key={i} className="py-2.5 flex items-center justify-between gap-3 text-xs">
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className={`px-2 py-0.5 rounded-md font-mono text-[10px] font-medium tracking-wider shrink-0 uppercase ${
                        e.type === "alert" || e.type === "incident" ? "bg-danger-500/15 text-danger-400" :
                        e.type === "security" ? "bg-warn-500/15 text-warn-400" :
                        e.type === "deploy" ? "bg-rust-500/15 text-rust-400" :
                        "bg-dark-700 text-dark-200"
                      }`}>{e.type}</span>
                      <span className="text-dark-200 font-mono truncate">{e.detail}</span>
                      {e.target && <span className="text-dark-400 font-mono truncate">· {e.target}</span>}
                    </div>
                    <span className="text-dark-400 text-xs shrink-0">{timeAgo(e.created_at)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
          </div>

          {/* Active Issues + SSL - side by side when both have content; a solo
              panel spans the full row instead of sitting at half width in an
              empty 2-col grid (the "Active Issues looks narrower than Recent
              Activity/Recommendations" report - it only IS narrower than its
              full-width siblings when SSL has nothing to show beside it). */}
          {intel && (() => {
            const showIssues = isVisible("issues") && intel.top_issues.length > 0;
            const showSsl = isVisible("ssl_countdown") && intel.ssl_countdowns.length > 0;
            if (!showIssues && !showSsl) return null;
            const solo = showIssues !== showSsl;
            return (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-6">
              {showIssues && (
                <div className={`${CARD} ${solo ? "lg:col-span-2" : ""}`}>
                  <div className={CARD_HEAD}>
                    <h3 className={CARD_TITLE}>Active Issues</h3>
                    <Link to={REC_ACTION_ROUTES.alerts} className={CARD_LINK}>View all</Link>
                  </div>
                  <div className={ROWS}>
                    {intel.top_issues.slice(0, 4).map((issue, i) => (
                      <div key={i} className="py-2.5 flex items-start gap-2.5">
                        <div className={`w-2 h-2 rounded-full mt-[5px] flex-shrink-0 ${
                          issue.severity === "critical" ? "bg-danger-500" :
                          issue.severity === "warning" ? "bg-warn-500" : "bg-accent-500"
                        }`} />
                        <p className="text-[13px] text-dark-100 leading-snug">{issue.title}</p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {showSsl && (
                <div className={`${CARD} ${solo ? "lg:col-span-2" : ""}`}>
                  <div className={CARD_HEAD}>
                    <h3 className={CARD_TITLE}>SSL Certificates</h3>
                  </div>
                  <div className={ROWS}>
                    {intel.ssl_countdowns.map((ssl, i) => (
                      <div key={i} className="py-2.5 flex items-center justify-between gap-3">
                        <span className="text-[13px] text-dark-100 font-mono truncate max-w-[260px] flex items-center gap-2">
                          {ssl.domain}
                          {/* A stack and a site can share the same domain string;
                              this is the only cue on the tile for which one is
                              expiring. */}
                          {ssl.stack_id && (
                            <span className="font-sans text-[10px] font-semibold px-1.5 py-0.5 rounded-md bg-accent-500/10 text-accent-400 uppercase tracking-wider shrink-0">Stack</span>
                          )}
                        </span>
                        <span className={`font-mono text-xs font-semibold shrink-0 ${
                          ssl.severity === "critical" ? "text-danger-400" :
                          ssl.severity === "warning" ? "text-warn-400" :
                          ssl.severity === "info" ? "text-accent-400" : "text-rust-400"
                        }`}>{ssl.days_left}d left</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
            );
          })()}

          {/* Smart Recommendations */}
          {intel && intel.recommendations && intel.recommendations.length > 0 && (
            <div className={`${CARD} mb-6`}>
              <div className={CARD_HEAD}>
                <h3 className={CARD_TITLE}>Recommendations</h3>
                <span className="font-mono text-xs text-dark-400">{intel.recommendations.length} item{intel.recommendations.length !== 1 ? "s" : ""}</span>
              </div>
              <div className={ROWS}>
                {intel.recommendations.map((rec, i) => {
                  // The recommendation itself is worth showing to whoever it is
                  // about - a client whose own site has no recent backup should
                  // hear that. Its ACTION is a different question: three of these
                  // six routes are administrator-only, and a chevron into one of
                  // them lands the caller straight back on this page with nothing
                  // said. Ask the same registry the sidebar and the command
                  // palette ask, so the answer cannot drift from theirs; a row
                  // whose destination is not for this caller keeps the message
                  // and loses the link.
                  const target = REC_ACTION_ROUTES[rec.action];
                  const route = target && isNavVisible(navFlagsFor(target), user?.role ?? "") ? target : undefined;
                  const inner = (
                    <>
                      <div className={`w-2 h-2 rounded-full flex-shrink-0 ${
                        rec.severity === "critical" ? "bg-danger-500" :
                        rec.severity === "warning" ? "bg-warn-500" : "bg-accent-500"
                      }`} />
                      <div className="flex-1 min-w-0">
                        <p className={`text-[13px] leading-snug ${
                          rec.severity === "critical" ? "text-danger-400" :
                          rec.severity === "warning" ? "text-warn-400" : "text-dark-100"
                        }`}>{rec.message}</p>
                      </div>
                      <span className={`text-[10px] px-2 py-0.5 rounded-md uppercase tracking-wider font-bold flex-shrink-0 ${
                        rec.severity === "critical" ? "bg-danger-500/10 text-danger-400" :
                        rec.severity === "warning" ? "bg-warn-500/10 text-warn-400" : "bg-accent-500/10 text-accent-400"
                      }`}>{rec.severity}</span>
                      {route && (
                        <svg className="w-4 h-4 text-dark-400 flex-shrink-0 group-hover:text-dark-200 transition-colors" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} aria-hidden="true"><path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" /></svg>
                      )}
                    </>
                  );
                  return route ? (
                    <Link key={i} to={route} className="-mx-2 px-2 min-h-[44px] py-2 flex items-center gap-2.5 rounded-md hover:bg-dark-700/40 transition-colors group">
                      {inner}
                    </Link>
                  ) : (
                    <div key={i} className="min-h-[44px] py-2 flex items-center gap-2.5">
                      {inner}
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* System Information - moved to above metrics */}

          {/* Feature #12: Quick Links / Bookmarks */}
          {(bookmarks.length > 0 || showAddBookmark) && isVisible("bookmarks") && (
            <div className={`${CARD} mb-6`}>
              <div className={CARD_HEAD}>
                <h3 className={CARD_TITLE}>Quick Links</h3>
                <button onClick={() => setShowAddBookmark(!showAddBookmark)} className={`inline-flex items-center min-h-9 px-3 rounded-lg border text-[13px] font-medium transition-colors ${BTN_2ND}`}>
                  {showAddBookmark ? "Cancel" : "+ Add"}
                </button>
              </div>
              {showAddBookmark && (
                <div className="pt-3 flex flex-col sm:flex-row gap-2">
                  <input value={bmLabel} onChange={e => setBmLabel(e.target.value)} placeholder="Label"
                    className="flex-1 px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-[13px] text-dark-100 placeholder-dark-400 min-h-[44px] sm:min-h-10" />
                  <input value={bmUrl} onChange={e => setBmUrl(e.target.value)} placeholder="/sites or https://..."
                    className="flex-[2_1_0%] px-3 py-2 bg-dark-900 border border-dark-600 rounded-lg text-[13px] text-dark-100 placeholder-dark-400 min-h-[44px] sm:min-h-10" />
                  <button onClick={() => {
                    if (bmLabel && bmUrl) {
                      const next = [...bookmarks, { label: bmLabel, url: bmUrl }];
                      setBookmarks(next);
                      localStorage.setItem('dp-dashboard-bookmarks', JSON.stringify(next));
                      setBmLabel(""); setBmUrl(""); setShowAddBookmark(false);
                    }
                  }} className="px-4 py-2 bg-rust-500 hover:bg-rust-600 text-white rounded-lg text-[13px] font-semibold min-h-[44px] sm:min-h-10 transition-colors">Add</button>
                </div>
              )}
              <div className="pt-3 grid grid-cols-[repeat(auto-fill,minmax(min(100%,180px),1fr))] gap-2 empty:hidden">
                {bookmarks.map((bm, i) => (
                  <div key={i} className="min-h-[44px] pl-3.5 pr-1.5 rounded-lg border border-dark-600 bg-dark-900/50 flex items-center justify-between gap-1.5 min-w-0 group">
                    <a href={(() => { const u = String(bm.url || ''); return /^https?:\/\//i.test(u) ? u : /^\/[^/]/.test(u) ? u : '#'; })()} target="_blank" rel="noopener noreferrer" className="text-[13px] font-medium text-dark-100 hover:text-rust-400 truncate">{String(bm.label || '')}</a>
                    <button onClick={() => {
                      const next = bookmarks.filter((_, j) => j !== i);
                      setBookmarks(next);
                      localStorage.setItem('dp-dashboard-bookmarks', JSON.stringify(next));
                    }} className="w-8 h-8 shrink-0 rounded-md text-dark-400 hover:text-danger-400 text-base leading-none sm:opacity-60 group-hover:opacity-100 focus-visible:opacity-100 transition-opacity">&times;</button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Network & Processes */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-start">
            {/* Network I/O */}
            {isVisible("network") && network.length > 0 && (
              <div className={`${CARD} overflow-x-auto`}>
                <div className="pb-2">
                  <h3 className={CARD_TITLE}>Network I/O</h3>
                </div>
                <table className="w-full text-[13px]">
                  <thead>
                    <tr>
                      <th className={`${TH} text-left`}>Interface</th>
                      <th className={`${TH} text-right`}>RX</th>
                      <th className={`${TH} text-right`}>TX</th>
                    </tr>
                  </thead>
                  <tbody className={ROWS}>
                    {network.filter(n => n.rx_bytes > 0 || n.tx_bytes > 0).map((iface) => (
                      <tr key={iface.name} className="hover:bg-dark-700/30 transition-colors">
                        <td className={`${TD} text-dark-50 font-mono`}>{iface.name}</td>
                        <td className={`${TD} text-right font-mono`}>
                          <div className="text-rust-400">
                            <span className="text-dark-400 mr-0.5">{"\u2193"}</span>
                            {iface.rx_rate != null ? formatRate(iface.rx_rate) : formatSize(iface.rx_bytes)}
                          </div>
                          {iface.rx_rate != null && (
                            <div className="text-[11px] text-dark-400 mt-0.5">{formatSize(iface.rx_bytes)} total</div>
                          )}
                        </td>
                        <td className={`${TD} text-right font-mono`}>
                          <div className="text-accent-400">
                            <span className="text-dark-400 mr-0.5">{"\u2191"}</span>
                            {iface.tx_rate != null ? formatRate(iface.tx_rate) : formatSize(iface.tx_bytes)}
                          </div>
                          {iface.tx_rate != null && (
                            <div className="text-[11px] text-dark-400 mt-0.5">{formatSize(iface.tx_bytes)} total</div>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Top Processes */}
            {isVisible("processes") && processes.length > 0 && (
              <div className={`${CARD} overflow-x-auto`}>
                <div className="pb-2">
                  <h3 className={CARD_TITLE}>Top Processes</h3>
                </div>
                <table className="w-full text-[13px]">
                  <thead>
                    <tr>
                      <th className={`${TH} text-left`}>Process</th>
                      <th className={`${TH} text-right`}>PID</th>
                      <th className={`${TH} text-right`}>CPU</th>
                      <th className={`${TH} text-right`}>MEM</th>
                    </tr>
                  </thead>
                  <tbody className={ROWS}>
                    {processes.slice(0, 10).map((p) => (
                      <tr key={p.pid} className="hover:bg-dark-700/30 transition-colors">
                        <td className={`${TD} text-dark-50 font-mono truncate max-w-[200px]`}>{p.name}</td>
                        <td className={`${TD} text-dark-200 text-right font-mono`}>{p.pid}</td>
                        <td className={`${TD} text-right font-mono`}>
                          <span className={p.cpu_pct > 50 ? "text-danger-400 font-medium" : "text-dark-200"}>
                            {p.cpu_pct.toFixed(1)}%
                          </span>
                        </td>
                        <td className={`${TD} text-dark-200 text-right font-mono`}>{p.mem_mb.toFixed(0)} MB</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
