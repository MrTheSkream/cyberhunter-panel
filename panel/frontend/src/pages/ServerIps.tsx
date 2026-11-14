import { useState, useEffect, useCallback, type ReactNode } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useServer } from "../context/ServerContext";
import { api, ApiError } from "../api";
import { formatDate } from "../utils/format";
import ConfirmDialog from "../components/ConfirmDialog";
import type { ServerIp } from "../utils/serverIps";

/** `GET /api/server-ips/discover`: on the interface, not yet declared. */
interface DiscoveredIp {
  ip: string;
  prefix: number;
  interface: string | null;
  managed: boolean;
  primary: boolean;
}

interface Conflict {
  ip: string;
  error: string;
  sites: string[];
  mail_domains: string[];
}

const inputCls =
  "w-full px-3 py-2 border border-dark-500 rounded-lg text-sm focus:ring-2 focus:ring-accent-500 focus:border-accent-500 outline-none";
const btnPrimary =
  "px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50 transition-colors";
const btnSecondary =
  "px-4 py-2 text-sm text-dark-300 border border-dark-600 rounded-lg hover:text-dark-100 hover:border-dark-400 transition-colors";

function Badge({ tone, children }: { tone: "rust" | "accent" | "dark" | "warn" | "danger"; children: ReactNode }) {
  const cls = {
    rust: "bg-rust-500/15 text-rust-400",
    accent: "bg-accent-500/15 text-accent-400",
    dark: "bg-dark-600 text-dark-200",
    warn: "bg-warn-500/15 text-warn-400",
    danger: "bg-danger-500/15 text-danger-400",
  }[tone];
  return <span className={`inline-flex px-2 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider ${cls}`}>{children}</span>;
}

export default function ServerIps() {
  const { user: authUser } = useAuth();
  // Ahead of the loader effect, as in ContainerPolicies: a non-admin must not
  // spend the mount on a 403.
  if (authUser?.role !== "admin") return <Navigate to="/" replace />;
  const { activeServer, activeServerId } = useServer();

  const [ips, setIps] = useState<ServerIp[]>([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState({ text: "", type: "" });
  const [busyId, setBusyId] = useState<string | null>(null);

  // Add modal
  const [showAdd, setShowAdd] = useState(false);
  const [addIp, setAddIp] = useState("");
  const [addPrefix, setAddPrefix] = useState("32");
  const [addInterface, setAddInterface] = useState("");
  const [addLabel, setAddLabel] = useState("");
  const [addToSystem, setAddToSystem] = useState(true);
  const [adding, setAdding] = useState(false);
  const [addError, setAddError] = useState("");

  // Discover modal
  const [showDiscover, setShowDiscover] = useState(false);
  const [discovered, setDiscovered] = useState<DiscoveredIp[] | null>(null);
  const [discoverError, setDiscoverError] = useState("");
  const [declaring, setDeclaring] = useState<string | null>(null);

  // Edit modal
  const [editing, setEditing] = useState<ServerIp | null>(null);
  const [editLabel, setEditLabel] = useState("");
  const [editPublicIp, setEditPublicIp] = useState("");
  const [savingEdit, setSavingEdit] = useState(false);
  const [editError, setEditError] = useState("");

  // Delete
  const [deleting, setDeleting] = useState<ServerIp | null>(null);
  const [removeFromSystem, setRemoveFromSystem] = useState(true);
  const [conflict, setConflict] = useState<Conflict | null>(null);

  const load = useCallback(async () => {
    try {
      const data = await api.get<ServerIp[]>("/server-ips");
      setIps(Array.isArray(data) ? data : []);
    } catch (e) {
      setMessage({ text: e instanceof Error ? e.message : "Failed to load IP addresses", type: "error" });
    } finally {
      setLoading(false);
    }
  }, []);

  // The list is per server (X-Server-Id), so it follows the server switcher.
  useEffect(() => { setLoading(true); load(); }, [load, activeServerId]);

  const replaceIp = (updated: ServerIp) =>
    setIps((prev) => prev.map((x) => (x.id === updated.id ? updated : x)));

  // ── Add ──────────────────────────────────────────────────────────────────
  const openAdd = () => {
    setAddIp(""); setAddPrefix("32"); setAddInterface(""); setAddLabel("");
    setAddToSystem(true); setAddError(""); setShowAdd(true);
  };

  const handleAdd = async () => {
    setAdding(true);
    setAddError("");
    try {
      const body: Record<string, unknown> = {
        ip: addIp.trim(),
        prefix: parseInt(addPrefix) || 32,
        add_to_system: addToSystem,
      };
      if (addInterface.trim()) body.interface = addInterface.trim();
      if (addLabel.trim()) body.label = addLabel.trim();
      const created = await api.post<ServerIp>("/server-ips", body);
      setShowAdd(false);
      setMessage({
        text: addToSystem ? `${created.ip} added to the server and declared` : `${created.ip} declared`,
        type: "success",
      });
      load();
    } catch (e) {
      setAddError(e instanceof Error ? e.message : "Failed to add IP");
    } finally {
      setAdding(false);
    }
  };

  // ── Discover ─────────────────────────────────────────────────────────────
  const openDiscover = async () => {
    setShowDiscover(true);
    setDiscovered(null);
    setDiscoverError("");
    try {
      const data = await api.get<DiscoveredIp[]>("/server-ips/discover");
      setDiscovered(Array.isArray(data) ? data : []);
    } catch (e) {
      setDiscoverError(e instanceof Error ? e.message : "Discovery failed");
      setDiscovered([]);
    }
  };

  const handleDeclare = async (d: DiscoveredIp) => {
    setDeclaring(d.ip);
    setDiscoverError("");
    try {
      const body: Record<string, unknown> = { ip: d.ip, prefix: d.prefix, add_to_system: false };
      if (d.interface) body.interface = d.interface;
      await api.post<ServerIp>("/server-ips", body);
      setDiscovered((prev) => (prev || []).filter((x) => x.ip !== d.ip));
      setMessage({ text: `${d.ip} declared`, type: "success" });
      load();
    } catch (e) {
      setDiscoverError(e instanceof Error ? e.message : "Failed to declare IP");
    } finally {
      setDeclaring(null);
    }
  };

  // ── Edit ─────────────────────────────────────────────────────────────────
  const openEdit = (ip: ServerIp) => {
    setEditing(ip);
    setEditLabel(ip.label || "");
    setEditPublicIp(ip.public_ip || "");
    setEditError("");
  };

  const handleSaveEdit = async () => {
    if (!editing) return;
    setSavingEdit(true);
    setEditError("");
    try {
      // Empty field = clear it, sent as null (not "").
      const updated = await api.put<ServerIp>(`/server-ips/${editing.id}`, {
        label: editLabel.trim() || null,
        public_ip: editPublicIp.trim() || null,
      });
      replaceIp(updated);
      setEditing(null);
      setMessage({ text: `${updated.ip} updated`, type: "success" });
    } catch (e) {
      setEditError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSavingEdit(false);
    }
  };

  // ── Refresh PTR ──────────────────────────────────────────────────────────
  const handleRefreshPtr = async (ip: ServerIp) => {
    setBusyId(ip.id);
    setMessage({ text: "", type: "" });
    try {
      const updated = await api.post<ServerIp>(`/server-ips/${ip.id}/refresh-ptr`);
      replaceIp(updated);
      setMessage({
        text: updated.ptr ? `PTR of ${updated.ip}: ${updated.ptr}` : `${updated.ip} still has no reverse DNS (PTR)`,
        type: updated.ptr ? "success" : "error",
      });
    } catch (e) {
      setMessage({ text: e instanceof Error ? e.message : "PTR refresh failed", type: "error" });
    } finally {
      setBusyId(null);
    }
  };

  // ── Delete ───────────────────────────────────────────────────────────────
  const openDelete = (ip: ServerIp) => {
    setDeleting(ip);
    setRemoveFromSystem(ip.managed && !ip.is_primary);
  };

  const cancelDelete = useCallback(() => setDeleting(null), []);

  const handleDelete = async () => {
    const target = deleting;
    if (!target) return;
    setDeleting(null);
    setBusyId(target.id);
    setMessage({ text: "", type: "" });
    const remove = target.managed && !target.is_primary && removeFromSystem;
    try {
      const res = await api.delete<{ ok: boolean; removed_from_system?: boolean }>(
        `/server-ips/${target.id}?remove_from_system=${remove ? "true" : "false"}`,
      );
      setIps((prev) => prev.filter((x) => x.id !== target.id));
      setMessage({
        text: res?.removed_from_system
          ? `${target.ip} removed from the panel and from the network interface`
          : `${target.ip} removed from the panel (still configured on the system)`,
        type: "success",
      });
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        const b = (e.body || {}) as { sites?: unknown; mail_domains?: unknown };
        setConflict({
          ip: target.ip,
          error: e.message,
          sites: Array.isArray(b.sites) ? (b.sites as string[]) : [],
          mail_domains: Array.isArray(b.mail_domains) ? (b.mail_domains as string[]) : [],
        });
      } else {
        setMessage({ text: e instanceof Error ? e.message : "Delete failed", type: "error" });
      }
    } finally {
      setBusyId(null);
    }
  };

  const missingPtr = ips.filter((x) => !x.ptr);

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-dark-50">IP Addresses</h1>
          <p className="text-sm text-dark-300 mt-1">
            IPv4 addresses of {activeServer ? <span className="font-mono">{activeServer.name}</span> : "this server"} that sites and mail can use
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={openDiscover} className={btnSecondary}>Discover</button>
          <button onClick={openAdd} className="flex items-center gap-2 px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 transition-colors">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" /></svg>
            Add IP
          </button>
        </div>
      </div>

      {message.text && (
        <div className={`px-4 py-3 rounded-lg text-sm border ${message.type === "success" ? "bg-rust-500/10 text-rust-400 border-rust-500/20" : "bg-danger-500/10 text-danger-400 border-danger-500/20"}`}>
          {message.text}
        </div>
      )}

      {missingPtr.length > 0 && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-warn-500/10 text-warn-400 border-warn-500/20">
          <p className="font-medium">
            No reverse DNS (PTR) for {missingPtr.map((x) => x.public_ip || x.ip).join(", ")}
          </p>
          <p className="text-xs mt-1">
            Mail sent from this IP will likely be rejected. Set the PTR at your provider (e.g. the OVH control panel), then use Refresh PTR.
          </p>
        </div>
      )}

      {conflict && (
        <div className="px-4 py-3 rounded-lg text-sm border bg-danger-500/10 text-danger-400 border-danger-500/20">
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="font-medium">{conflict.ip} is still in use and was not removed.</p>
              {conflict.error && <p className="text-xs mt-1">{conflict.error}</p>}
            </div>
            <button onClick={() => setConflict(null)} className="text-xs text-danger-300 hover:text-danger-200 shrink-0">Dismiss</button>
          </div>
          {conflict.sites.length > 0 && (
            <p className="text-xs mt-2"><span className="text-dark-200">Sites:</span> <span className="font-mono">{conflict.sites.join(", ")}</span></p>
          )}
          {conflict.mail_domains.length > 0 && (
            <p className="text-xs mt-1"><span className="text-dark-200">Mail domains (forced sending IP):</span> <span className="font-mono">{conflict.mail_domains.join(", ")}</span></p>
          )}
          <p className="text-xs mt-2 text-dark-300">Move these to another IP first (site page → IP address, Mail → domain → Settings).</p>
        </div>
      )}

      {/* Table */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-dark-600 bg-dark-700/50">
              <th className="text-left px-4 py-3 text-xs font-medium text-dark-300 uppercase">IP</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-dark-300 uppercase">Interface</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-dark-300 uppercase">Reverse DNS (PTR)</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-dark-300 uppercase">Origin</th>
              <th className="text-center px-4 py-3 text-xs font-medium text-dark-300 uppercase">Sites</th>
              <th className="text-center px-4 py-3 text-xs font-medium text-dark-300 uppercase">Mail</th>
              <th className="text-right px-4 py-3 text-xs font-medium text-dark-300 uppercase">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-8 text-dark-400">Loading...</td></tr>
            ) : ips.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-8 text-dark-400">No IP declared yet. Use Discover to declare the addresses already on this server, or Add IP.</td></tr>
            ) : (
              ips.map((ip) => (
                <tr key={ip.id} className="border-b border-dark-700 hover:bg-dark-700/30 align-top">
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-dark-50">{ip.ip}/{ip.prefix}</span>
                      {ip.is_primary && <Badge tone="accent">Primary</Badge>}
                      {!ip.on_system && <Badge tone="danger">Not on interface</Badge>}
                    </div>
                    {ip.public_ip && <p className="text-xs text-dark-300 mt-0.5">Public: <span className="font-mono">{ip.public_ip}</span></p>}
                    {ip.label && <p className="text-xs text-dark-300 mt-0.5">{ip.label}</p>}
                    {!ip.on_system && (
                      <p className="text-[11px] text-danger-400 mt-1 max-w-xs">
                        The agent no longer sees this IP on the server. Sites bound to it will fail until it is back.
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3 font-mono text-dark-200">{ip.interface || "—"}</td>
                  <td className="px-4 py-3">
                    {ip.ptr ? (
                      <span className="font-mono text-dark-100">{ip.ptr}</span>
                    ) : (
                      <span className="text-warn-400">None</span>
                    )}
                    {ip.ptr_checked_at && (
                      <p className="text-[11px] text-dark-400 mt-0.5">checked {formatDate(ip.ptr_checked_at)}</p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {ip.managed ? <Badge tone="rust">Panel</Badge> : <Badge tone="dark">System</Badge>}
                  </td>
                  <td className="text-center px-4 py-3 text-dark-200 font-mono">{ip.site_count}</td>
                  <td className="text-center px-4 py-3 text-dark-200 font-mono">{ip.mail_domain_count}</td>
                  <td className="text-right px-4 py-3 whitespace-nowrap">
                    <button onClick={() => handleRefreshPtr(ip)} disabled={busyId === ip.id} className="text-xs text-accent-400 hover:text-accent-300 disabled:opacity-50 mr-3">
                      {busyId === ip.id ? "Working..." : "Refresh PTR"}
                    </button>
                    <button onClick={() => openEdit(ip)} className="text-xs text-accent-400 hover:text-accent-300 mr-3">Edit</button>
                    <button onClick={() => openDelete(ip)} disabled={busyId === ip.id} className="text-xs text-danger-400 hover:text-danger-300 disabled:opacity-50">Remove</button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Info */}
      <div className="bg-dark-800 rounded-lg border border-dark-500 p-5">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest mb-3">How It Works</h3>
        <div className="space-y-2 text-sm text-dark-200">
          <p><strong className="text-dark-100">Origin</strong> — <em>Panel</em>: the panel put this IP on the network interface and can remove it. <em>System</em>: the IP was configured outside the panel (provider, cloud-init, another tool); it can be used, but the panel never removes it from the server.</p>
          <p><strong className="text-dark-100">Sites</strong> — each site listens on one IP (the primary IP by default). Change it on the site page.</p>
          <p><strong className="text-dark-100">Mail</strong> — a mail domain sends from the IP of the website with the same name, unless a sending IP is forced in Mail → domain → Settings. The HELO name is the IP's PTR, so every sending IP needs a reverse DNS that points back to it.</p>
          <p className="text-xs text-dark-400">IPv6 stays shared by all sites. Docker apps and the panel itself always use the primary IP.</p>
        </div>
      </div>

      {/* Add modal */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowAdd(false)}>
          <div className="bg-dark-800 rounded-lg border border-dark-500 p-6 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-dark-50 mb-1">Add IP</h2>
            <p className="text-xs text-dark-300 mb-4">
              The IP must first be routed to this server by your provider (e.g. attached as an Additional IP in the OVH control panel).
            </p>
            <div className="space-y-4">
              <div className="grid grid-cols-3 gap-4">
                <div className="col-span-2">
                  <label className="block text-sm text-dark-200 mb-1">IPv4 address</label>
                  <input type="text" value={addIp} onChange={(e) => setAddIp(e.target.value)} placeholder="192.0.2.107" className={`${inputCls} font-mono`} autoFocus />
                </div>
                <div>
                  <label className="block text-sm text-dark-200 mb-1">Prefix</label>
                  <input type="number" min={8} max={32} value={addPrefix} onChange={(e) => setAddPrefix(e.target.value)} className={inputCls} />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-dark-200 mb-1">Interface <span className="text-dark-400">(optional)</span></label>
                  <input type="text" value={addInterface} onChange={(e) => setAddInterface(e.target.value)} placeholder="default route" className={`${inputCls} font-mono`} />
                </div>
                <div>
                  <label className="block text-sm text-dark-200 mb-1">Label <span className="text-dark-400">(optional)</span></label>
                  <input type="text" value={addLabel} onChange={(e) => setAddLabel(e.target.value)} maxLength={100} placeholder="Mail IP" className={inputCls} />
                </div>
              </div>
              <label className="flex items-start gap-2 text-sm text-dark-100 cursor-pointer select-none">
                <input type="checkbox" checked={addToSystem} onChange={(e) => setAddToSystem(e.target.checked)} className="mt-0.5" />
                <span>
                  Add to the server's network interface
                  <span className="block text-xs text-dark-400 mt-0.5">
                    {addToSystem
                      ? "The panel adds the IP live and persists it in netplan (no network restart)."
                      : "Only declare it: the IP is already configured on the server."}
                  </span>
                </span>
              </label>
              {addError && <p className="text-sm text-danger-400">{addError}</p>}
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setShowAdd(false)} className={btnSecondary}>Cancel</button>
              <button onClick={handleAdd} disabled={adding || !addIp.trim()} className={btnPrimary}>
                {adding ? "Adding..." : "Add IP"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Discover modal */}
      {showDiscover && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setShowDiscover(false)}>
          <div className="bg-dark-800 rounded-lg border border-dark-500 p-6 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-dark-50 mb-1">Discover IPs</h2>
            <p className="text-xs text-dark-300 mb-4">IPv4 addresses already configured on this server that the panel does not know yet. Declaring one does not change the server.</p>
            {discoverError && <p className="text-sm text-danger-400 mb-3">{discoverError}</p>}
            {discovered === null ? (
              <p className="text-sm text-dark-400 py-6 text-center">Scanning...</p>
            ) : discovered.length === 0 ? (
              <p className="text-sm text-dark-400 py-6 text-center">Nothing new: every IP on the server is already declared.</p>
            ) : (
              <div className="divide-y divide-dark-600 border border-dark-600 rounded-lg">
                {discovered.map((d) => (
                  <div key={d.ip} className="flex items-center justify-between px-4 py-3">
                    <div>
                      <span className="font-mono text-sm text-dark-50">{d.ip}/{d.prefix}</span>
                      <span className="text-xs text-dark-400 ml-2 font-mono">{d.interface || ""}</span>
                      <div className="flex gap-1 mt-1">
                        {d.primary && <Badge tone="accent">Primary</Badge>}
                        {d.managed ? <Badge tone="rust">Panel</Badge> : <Badge tone="dark">System</Badge>}
                      </div>
                    </div>
                    <button onClick={() => handleDeclare(d)} disabled={declaring !== null} className="px-3 py-1.5 bg-rust-500 text-white rounded text-xs font-medium hover:bg-rust-600 disabled:opacity-50">
                      {declaring === d.ip ? "Declaring..." : "Declare"}
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="flex justify-end mt-6">
              <button onClick={() => setShowDiscover(false)} className={btnSecondary}>Close</button>
            </div>
          </div>
        </div>
      )}

      {/* Edit modal */}
      {editing && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setEditing(null)}>
          <div className="bg-dark-800 rounded-lg border border-dark-500 p-6 w-full max-w-lg" onClick={(e) => e.stopPropagation()}>
            <h2 className="text-lg font-semibold text-dark-50 mb-4">Edit <span className="font-mono">{editing.ip}</span></h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-dark-200 mb-1">Label</label>
                <input type="text" value={editLabel} onChange={(e) => setEditLabel(e.target.value)} maxLength={100} className={inputCls} />
              </div>
              <div>
                <label className="block text-sm text-dark-200 mb-1">Public IP</label>
                <input type="text" value={editPublicIp} onChange={(e) => setEditPublicIp(e.target.value)} placeholder={editing.ip} className={`${inputCls} font-mono`} />
                <p className="text-xs text-dark-400 mt-1">
                  Only if the server is behind NAT and this address is not the one the Internet sees. Leave empty otherwise. It is used for DNS records (A, SPF).
                </p>
              </div>
              {editError && <p className="text-sm text-danger-400">{editError}</p>}
            </div>
            <div className="flex justify-end gap-2 mt-6">
              <button onClick={() => setEditing(null)} className={btnSecondary}>Cancel</button>
              <button onClick={handleSaveEdit} disabled={savingEdit} className={btnPrimary}>
                {savingEdit ? "Saving..." : "Save"}
              </button>
            </div>
          </div>
        </div>
      )}

      {deleting && (
        <ConfirmDialog
          label={`Remove ${deleting.ip} from the panel?${
            deleting.site_count + deleting.mail_domain_count > 0
              ? `\nIt is still used by ${deleting.site_count} site(s) and ${deleting.mail_domain_count} mail domain(s); the removal will be refused until they are moved.`
              : ""
          }`}
          confirmLabel="Remove"
          onConfirm={handleDelete}
          onCancel={cancelDelete}
        >
          {deleting.managed && !deleting.is_primary ? (
            <label className="flex items-start gap-2 text-sm text-dark-100 cursor-pointer select-none">
              <input type="checkbox" checked={removeFromSystem} onChange={(e) => setRemoveFromSystem(e.target.checked)} className="mt-0.5" />
              <span>
                Also remove it from the network interface
                <span className="block text-xs text-dark-400 mt-0.5">Otherwise the IP stays configured on the server, only undeclared in the panel.</span>
              </span>
            </label>
          ) : (
            <p className="text-xs text-dark-400">
              {deleting.is_primary
                ? "This is the server's primary IP: it stays on the server."
                : "This IP was configured outside the panel: it stays on the server."}
            </p>
          )}
        </ConfirmDialog>
      )}
    </div>
  );
}
