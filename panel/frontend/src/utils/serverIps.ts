import { useEffect, useState } from "react";
import { api } from "../api";
import { useServer } from "../context/ServerContext";

/** An IPv4 address declared for the active server (contract B, `GET /api/server-ips`). */
export interface ServerIp {
  id: string;
  server_id: string;
  ip: string;
  prefix: number;
  interface: string | null;
  /** Only set when the server sits behind NAT; null = same as `ip`. */
  public_ip: string | null;
  ptr: string | null;
  ptr_checked_at: string | null;
  /** true = put on the interface by the panel (60-dockpanel.yaml). */
  managed: boolean;
  label: string | null;
  created_at: string;
  site_count: number;
  mail_domain_count: number;
  /** Still present on the network interface, according to the agent. */
  on_system: boolean;
  /** The server's primary IP as detected by the agent. */
  is_primary: boolean;
}

/** Human label for an IP in a <select>. */
export function serverIpOptionLabel(ip: ServerIp): string {
  let s = ip.ip;
  if (ip.public_ip) s += ` (public ${ip.public_ip})`;
  if (ip.label) s += ` - ${ip.label}`;
  if (ip.is_primary) s += " [primary]";
  return s;
}

/**
 * Loads the active server's declared IPs. `/api/server-ips` is an admin route,
 * so nothing is fetched unless `enabled` (pass the admin test) - a non-admin
 * would only collect a 403.
 */
export function useServerIps(enabled: boolean) {
  const { activeServerId } = useServer();
  const [ips, setIps] = useState<ServerIp[]>([]);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    api
      .get<ServerIp[]>("/server-ips")
      .then((d) => { if (!cancelled) setIps(Array.isArray(d) ? d : []); })
      .catch(() => { if (!cancelled) setIps([]); })
      .finally(() => { if (!cancelled) setLoaded(true); });
    return () => { cancelled = true; };
  }, [enabled, activeServerId]);

  return { ips, loaded };
}
