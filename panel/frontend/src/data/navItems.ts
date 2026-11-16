export interface NavItem {
  to: string;
  label: string;
  iconName: string;
  adminOnly?: boolean;
  /** Visible to reseller role (and admin, unless `resellerOnly` says otherwise) */
  resellerVisible?: boolean;
  /**
   * The page answers only for the caller's OWN reseller tenant, so an admin -
   * who has no tenant - must NOT see it. `reseller_dashboard.rs:76` refuses them
   * by name, and an admin who followed the sidebar got that refusal rendered as
   * the whole page (issue #112). The admin counterpart is the `/resellers` row.
   *
   * Kept as a THIRD flag rather than a rename of `resellerVisible`: two absence
   * arms assert the /account row carries neither of these, and a rename would
   * leave them vacuously green while a live restriction existed outside their
   * view. Adding a flag means those arms have to learn about it, which is the
   * behaviour we want.
   */
  resellerOnly?: boolean;
  /**
   * Shown only to an admin whose panel account is linked to a Linux user for
   * the user terminal (`GET /api/terminal/user/me` answered `linked: true`).
   * The answer is held below, outside React, because this registry is read
   * synchronously by every menu.
   */
  requiresUserTerminal?: boolean;
}

// ── User terminal link (the "My session" row) ──
//
// Cached per browser so the row is drawn on the first render after a reload,
// and refreshed at boot, after sign-in and whenever /terminal/me loads. A plain
// `fetch`, not `api.get`: a 401 here must never navigate anyone to /login.
const USER_TERMINAL_LINK_KEY = "dp-user-terminal-linked";

function readUserTerminalLink(): boolean {
  try {
    return localStorage.getItem(USER_TERMINAL_LINK_KEY) === "1";
  } catch {
    return false;
  }
}

let userTerminalLinked = readUserTerminalLink();

/** Fired on `window` whenever the cached answer changes, so the menu can redraw. */
export const USER_TERMINAL_LINK_EVENT = "dp-user-terminal-link";

export function isUserTerminalLinked(): boolean {
  return userTerminalLinked;
}

export function setUserTerminalLinked(linked: boolean): void {
  const changed = userTerminalLinked !== linked;
  userTerminalLinked = linked;
  if (changed) {
    try {
      window.dispatchEvent(new Event(USER_TERMINAL_LINK_EVENT));
    } catch {
      /* no window (tests): nothing to notify */
    }
  }
  try {
    if (linked) localStorage.setItem(USER_TERMINAL_LINK_KEY, "1");
    else localStorage.removeItem(USER_TERMINAL_LINK_KEY);
  } catch {
    /* storage unavailable: keep the in-memory answer */
  }
}

/** Re-asks the backend. Resolves with the answer, or the cached one on a network failure. */
export async function refreshUserTerminalLink(): Promise<boolean> {
  try {
    const res = await fetch("/api/terminal/user/me", {
      credentials: "same-origin",
      headers: { "X-Requested-With": "DockPanel" },
    });
    if (!res.ok) {
      setUserTerminalLinked(false);
      return false;
    }
    const data = (await res.json().catch(() => ({}))) as { linked?: boolean };
    setUserTerminalLinked(data.linked === true);
    return userTerminalLinked;
  } catch {
    return userTerminalLinked;
  }
}

export interface NavGroup {
  key: string;
  label: string;
  items: NavItem[];
}

/**
 * The ONE place that decides whether a role may be shown a navigation entry.
 *
 * This lived inline in `useLayoutState` and nowhere else, so the command palette
 * - a second menu over the same pages - simply never asked: Ctrl+K offered
 * /users, /secrets, /security and /settings to every account. Each of those
 * pages guards itself, so nothing leaked; what the palette handed out was a list
 * of doors that refuse, which is the same broken promise as a sidebar entry that
 * 403s. A decision inlined in two menus is a decision that drifts.
 */
export function isNavVisible(
  item: Pick<NavItem, "adminOnly" | "resellerVisible" | "resellerOnly" | "requiresUserTerminal">,
  role: string,
): boolean {
  // The user terminal is admin-only and needs a linked Linux account.
  if (item.requiresUserTerminal) return role === "admin" && userTerminalLinked;
  // Ahead of the admin branch, because it is the one kind of row "admin sees
  // everything" gets wrong: a tenant-scoped page has nothing to show an account
  // that is not a tenant, and the handler behind it says so with a 403.
  if (item.resellerOnly) return role === "reseller";
  // Admin sees everything else
  if (role === "admin") return true;
  // Reseller sees resellerVisible items + non-restricted items
  if (role === "reseller") return !!item.resellerVisible || (!item.adminOnly && !item.resellerVisible);
  // Everyone else (user / client): hide adminOnly and resellerVisible items
  return !item.adminOnly && !item.resellerVisible;
}

/**
 * The nav flags for a route, looked up from the registry above so callers cannot
 * carry their own copy. A path with no nav row is unrestricted - per-site tools
 * (/sites/:id/files, /sites/:id/backups) deliberately have no sidebar entry.
 */
export function navFlagsFor(
  path: string,
): Pick<NavItem, "adminOnly" | "resellerVisible" | "resellerOnly" | "requiresUserTerminal"> {
  const base = path.split("?")[0];
  for (const group of navGroups) {
    for (const item of group.items) {
      if (item.to === base) return item;
    }
  }
  return {};
}

export const navGroups: NavGroup[] = [
  {
    key: "hosting",
    label: "Hosting",
    items: [
      { to: "/", label: "Dashboard", iconName: "dashboard" },
      { to: "/sites", label: "Sites", iconName: "sites" },
      { to: "/databases", label: "Databases", iconName: "databases" },
      { to: "/wordpress-toolkit", label: "WP Toolkit", iconName: "wordpress", adminOnly: true },
      { to: "/apps", label: "Docker Apps", iconName: "apps", adminOnly: true },
      { to: "/git-deploys", label: "Git Deploy", iconName: "gitDeploys", adminOnly: true },
      { to: "/migration", label: "Migration", iconName: "migration", adminOnly: true },
    ],
  },
  {
    key: "reseller",
    label: "Reseller",
    items: [
      { to: "/reseller", label: "Reseller Panel", iconName: "reseller", resellerVisible: true, resellerOnly: true },
      { to: "/reseller/users", label: "My Users", iconName: "users", resellerVisible: true, resellerOnly: true },
      // The admin's half of this group. Everything an admin can do to a reseller
      // lives behind /api/resellers, which had eight handlers and no screen at
      // all until v2.118.0 - so the only reseller-shaped control the panel
      // offered an admin was the role dropdown in Users, which sets the role
      // without creating a profile and produces an account whose own panel
      // answers 404. This row is the door those handlers never had.
      { to: "/resellers", label: "Resellers", iconName: "reseller", adminOnly: true },
    ],
  },
  {
    key: "operations",
    label: "Operations",
    items: [
      { to: "/dns", label: "DNS", iconName: "dns", adminOnly: true },
      { to: "/cdn", label: "CDN", iconName: "dns", adminOnly: true },
      // Unrestricted since v2.103.0, and the flag's absence is the whole point.
      // The backend admits a mail domain to whoever owns the site of the same
      // name on the same server (`MAIL_DOMAIN_CALLER_PREDICATE`, backend
      // routes/mail.rs), and that test carries NO role term - a `client`, a
      // plain `user` and a `reseller` all reach it by the same route. There is
      // no flag here meaning "owner", because the registry only ever sees a
      // role string; ownership is not knowable at nav-render time. Restricting
      // this row to any single role would contradict the API in one direction
      // or the other. What the page SHOWS is decided in Mail.tsx, per caller.
      { to: "/mail", label: "Mail", iconName: "mail" },
      { to: "/backup-orchestrator", label: "Backup Manager", iconName: "backups", adminOnly: true },
      { to: "/monitoring", label: "Monitoring", iconName: "monitoring" },
      { to: "/notifications", label: "Notifications", iconName: "notifications" },
      { to: "/logs", label: "Logs", iconName: "logs", adminOnly: true },
      { to: "/terminal", label: "Terminal", iconName: "terminal" },
      // Full-screen page outside the layout: a shell as the linked Linux user,
      // attached to a persistent tmux session.
      { to: "/terminal/me", label: "My session", iconName: "terminal", requiresUserTerminal: true },
    ],
  },
  {
    key: "admin",
    label: "Admin",
    items: [
      { to: "/servers", label: "Servers", iconName: "servers", adminOnly: true },
      { to: "/ips", label: "IP Addresses", iconName: "dns", adminOnly: true },
      { to: "/php", label: "PHP", iconName: "servers", adminOnly: true },
      { to: "/users", label: "Users", iconName: "users", adminOnly: true },
      { to: "/container-policies", label: "Container Policies", iconName: "servers", adminOnly: true },
      { to: "/integrations", label: "Integrations", iconName: "extensions", adminOnly: true },
      { to: "/secrets", label: "Secrets", iconName: "secrets", adminOnly: true },
      { to: "/security", label: "Security", iconName: "security", adminOnly: true },
      { to: "/system", label: "System", iconName: "servers", adminOnly: true },
      { to: "/telemetry", label: "Telemetry", iconName: "monitoring", adminOnly: true },
      { to: "/settings", label: "Settings", iconName: "settings", adminOnly: true },
    ],
  },
  {
    key: "account",
    label: "Account",
    items: [
      // The ONLY entry every role can see, and the reason it exists: password
      // change, 2FA enrolment, passkeys, sessions and API keys all used to live
      // behind the `adminOnly` /settings row above, so a client had no door to
      // its own account at all. Never mark this `adminOnly` - the 2FA banner in
      // all four layouts points here, and a non-admin is exactly who it warns.
      { to: "/account", label: "My Account", iconName: "settings" },
    ],
  },
];
