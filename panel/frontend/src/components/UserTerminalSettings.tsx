import { useCallback, useEffect, useState } from "react";
import { api, ApiError } from "../api";

// Settings card for the user terminal: which Linux user each admin account
// opens at /terminal/me. One row per admin account.
//
// Every write (Save, Unlink) carries a fresh proof, a password or a TOTP code,
// checked by `require_enrolment_proof` on the backend. The agent validates the
// Linux user (uid range, shell, not a site account) before anything is stored,
// and its refusals come back as `reasons`.

interface Mapping {
  linux_user: string;
  uid: number | null;
  autostart_command: string | null;
  record: boolean;
  updated_at: string | null;
}

interface AdminAccount {
  user_id: string;
  email: string;
  mapping: Mapping | null;
}

interface CheckResult {
  supported?: boolean;
  ok?: boolean;
  reasons?: string[];
  uid?: number | null;
  home?: string | null;
  shell?: string | null;
  tmux_installed?: boolean;
  prepared?: boolean;
  linger?: boolean;
  session_running?: boolean;
  sudo_nopasswd?: boolean;
}

interface Proof {
  current_password?: string;
  code?: string;
}

type RowMsg = { text: string; type: "success" | "error"; reasons?: string[] } | null;

const MFA_MESSAGE = "Sign in again with two-factor authentication to manage user terminals.";

function asMapping(raw: Record<string, unknown> | null | undefined): Mapping | null {
  if (!raw || typeof raw.linux_user !== "string" || raw.linux_user === "") return null;
  return {
    linux_user: raw.linux_user,
    uid: typeof raw.uid === "number" ? raw.uid : null,
    autostart_command: typeof raw.autostart_command === "string" ? raw.autostart_command : null,
    record: raw.record === true,
    updated_at: typeof raw.updated_at === "string" ? raw.updated_at : null,
  };
}

// Accepts the list either bare or under `accounts`, and each mapping either
// flat on the account or nested under `mapping` (null when unlinked).
function parseAccounts(data: unknown): AdminAccount[] {
  const list = Array.isArray(data)
    ? data
    : Array.isArray((data as { accounts?: unknown })?.accounts)
      ? (data as { accounts: unknown[] }).accounts
      : [];
  return list
    .filter((a): a is Record<string, unknown> => !!a && typeof a === "object")
    .map((a) => {
      const nested = "mapping" in a ? (a.mapping as Record<string, unknown> | null) : a;
      return {
        user_id: String(a.user_id ?? ""),
        email: String(a.email ?? ""),
        mapping: asMapping(nested),
      };
    })
    .filter((a) => a.user_id !== "");
}

function errorText(e: unknown, fallback: string): string {
  if (e instanceof ApiError && e.code === "mfa_required") return MFA_MESSAGE;
  return e instanceof Error ? e.message : fallback;
}

function reasonsOf(e: unknown): string[] | undefined {
  if (!(e instanceof ApiError)) return undefined;
  const r = (e.body as { reasons?: unknown } | undefined)?.reasons;
  return Array.isArray(r) ? r.map(String) : undefined;
}

// `api.delete` sends no body, and Unlink has to carry the proof.
async function deleteWithBody(path: string, body: unknown): Promise<void> {
  const headers: Record<string, string> = {
    "X-Requested-With": "DockPanel",
    "Content-Type": "application/json",
  };
  const serverId = localStorage.getItem("dp-active-server");
  if (serverId) headers["X-Server-Id"] = serverId;
  const res = await fetch(`/api${path}`, {
    method: "DELETE",
    credentials: "same-origin",
    headers,
    body: JSON.stringify(body),
  });
  if (res.ok) return;
  const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  throw new ApiError(
    res.status,
    typeof data.error === "string" ? data.error : `Request failed (${res.status})`,
    typeof data.code === "string" ? data.code : undefined,
    data,
  );
}

export default function UserTerminalSettings() {
  const [accounts, setAccounts] = useState<AdminAccount[] | null>(null);
  const [loadError, setLoadError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await api.get<unknown>("/terminal/user/accounts");
      setAccounts(parseAccounts(data));
      setLoadError("");
    } catch (e) {
      setAccounts(null);
      setLoadError(errorText(e, "Failed to load accounts"));
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="bg-dark-800 rounded-lg border border-dark-500 overflow-hidden mt-4">
      <div className="px-5 py-3 border-b border-dark-600">
        <h3 className="text-xs font-medium text-dark-300 uppercase font-mono tracking-widest">User Terminal Accounts</h3>
        <p className="text-xs text-dark-200 mt-0.5">
          The Linux user each admin account opens at <code className="font-mono">/terminal/me</code>, in a persistent
          tmux session. Opening it requires a session signed in with two-factor authentication.
        </p>
      </div>
      {loadError && <p className="px-5 py-3 text-xs text-danger-400">{loadError}</p>}
      {!loadError && accounts === null && <p className="px-5 py-3 text-xs text-dark-400">Loading...</p>}
      {accounts !== null && accounts.length === 0 && (
        <p className="px-5 py-3 text-xs text-dark-400">No admin accounts.</p>
      )}
      {accounts !== null && accounts.length > 0 && (
        <div className="divide-y divide-dark-700">
          {accounts.map((a) => (
            <AccountRow key={a.user_id} account={a} onChanged={load} />
          ))}
        </div>
      )}
    </div>
  );
}

function AccountRow({ account, onChanged }: { account: AdminAccount; onChanged: () => Promise<void> }) {
  const m = account.mapping;
  const [linuxUser, setLinuxUser] = useState(m?.linux_user ?? "");
  const [startCommand, setStartCommand] = useState(m ? m.autostart_command ?? "" : "claude");
  const [record, setRecord] = useState(m?.record ?? false);
  const [msg, setMsg] = useState<RowMsg>(null);
  const [check, setCheck] = useState<CheckResult | null>(null);
  const [checking, setChecking] = useState(false);
  const [proofFor, setProofFor] = useState<"save" | "unlink" | null>(null);

  useEffect(() => {
    setLinuxUser(m?.linux_user ?? "");
    setStartCommand(m ? m.autostart_command ?? "" : "claude");
    setRecord(m?.record ?? false);
  }, [m]);

  const errText = (e: unknown) => errorText(e, "Request failed");

  const runCheck = async () => {
    setChecking(true);
    setMsg(null);
    try {
      const r = await api.get<CheckResult>(`/terminal/user/accounts/${account.user_id}/check`);
      setCheck(r);
    } catch (e) {
      setCheck(null);
      setMsg({ text: errText(e), type: "error", reasons: reasonsOf(e) });
    } finally {
      setChecking(false);
    }
  };

  const submit = async (proof: Proof) => {
    const action = proofFor;
    if (!action) return;
    if (action === "save") {
      await api.put(`/terminal/user/accounts/${account.user_id}`, {
        linux_user: linuxUser.trim(),
        autostart_command: startCommand.trim() === "" ? null : startCommand.trim(),
        record,
        proof,
      });
      setMsg({ text: `Linked to ${linuxUser.trim()}`, type: "success" });
    } else {
      await deleteWithBody(`/terminal/user/accounts/${account.user_id}`, { proof });
      setMsg({ text: "Unlinked. The tmux session and linger were left in place.", type: "success" });
    }
    setProofFor(null);
    setCheck(null);
    await onChanged();
  };

  const linuxUserValid = /^[a-z_][a-z0-9_-]{0,31}$/.test(linuxUser.trim());

  return (
    <div className="px-5 py-4 space-y-3">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-sm text-dark-100 break-all">{account.email}</p>
        <p className="text-xs font-mono text-dark-400">
          {m ? `Linked to ${m.linux_user}${m.uid !== null ? ` (uid ${m.uid})` : ""}` : "Not linked"}
        </p>
      </div>
      <div className="grid gap-3 sm:grid-cols-[1fr_1fr_auto] sm:items-end">
        <label className="block">
          <span className="block text-xs text-dark-300 mb-1">Linux user</span>
          <input
            type="text"
            value={linuxUser}
            onChange={(e) => setLinuxUser(e.target.value)}
            placeholder="bastien"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 outline-none bg-dark-700"
          />
        </label>
        <label className="block">
          <span className="block text-xs text-dark-300 mb-1">Start command</span>
          <input
            type="text"
            value={startCommand}
            onChange={(e) => setStartCommand(e.target.value)}
            placeholder="Empty: plain shell"
            maxLength={200}
            spellCheck={false}
            className="w-full px-3 py-2 border border-dark-500 rounded-lg text-sm font-mono focus:ring-2 focus:ring-accent-500 outline-none bg-dark-700"
          />
        </label>
        <label className="flex items-center gap-2 text-sm text-dark-200 sm:pb-2">
          <input type="checkbox" checked={record} onChange={(e) => setRecord(e.target.checked)} />
          Record sessions
        </label>
      </div>
      <p className="text-xs text-dark-400">
        The start command is typed into the tmux session when it starts. Recording writes everything shown, secrets
        included, to an asciicast file.
      </p>
      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => { setMsg(null); setProofFor("save"); }}
          disabled={!linuxUserValid}
          className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
        >
          Save
        </button>
        {m && (
          <button
            onClick={() => { setMsg(null); setProofFor("unlink"); }}
            className="px-4 py-2 bg-dark-700 text-dark-100 border border-dark-500 rounded-lg text-sm font-medium hover:border-dark-400"
          >
            Unlink
          </button>
        )}
        <button
          onClick={runCheck}
          disabled={!m || checking}
          title={m ? undefined : "Save a Linux user first"}
          className="px-4 py-2 bg-dark-700 text-dark-100 border border-dark-500 rounded-lg text-sm font-medium hover:border-dark-400 disabled:opacity-50"
        >
          {checking ? "Checking..." : "Check"}
        </button>
      </div>
      {linuxUser.trim() !== "" && !linuxUserValid && (
        <p className="text-xs text-warn-400">
          A Linux login is lowercase letters, digits, "_" or "-", starting with a letter or "_", 32 characters at most.
        </p>
      )}
      {msg && (
        <div className={`text-xs ${msg.type === "success" ? "text-rust-400" : "text-danger-400"}`} role="status">
          <p>{msg.text}</p>
          {msg.reasons && msg.reasons.length > 0 && (
            <ul className="list-disc ml-5 mt-1">
              {msg.reasons.map((r) => <li key={r}>{r}</li>)}
            </ul>
          )}
        </div>
      )}
      {check && <CheckReport result={check} />}
      {proofFor && (
        <ProofDialog
          title={proofFor === "save" ? `Link ${account.email} to ${linuxUser.trim()}` : `Unlink ${account.email}`}
          confirmLabel={proofFor === "save" ? "Save" : "Unlink"}
          onCancel={() => setProofFor(null)}
          onSubmit={submit}
        />
      )}
    </div>
  );
}

function CheckReport({ result }: { result: CheckResult }) {
  if (result.supported === false) {
    return <p className="text-xs text-warn-400">Not supported on this server.</p>;
  }
  const yesNo = (v: boolean | undefined) => (v === undefined ? "unknown" : v ? "yes" : "no");
  const rows: [string, string][] = [
    ["UID", result.uid != null ? String(result.uid) : "unknown"],
    ["Home", result.home ?? "unknown"],
    ["Shell", result.shell ?? "unknown"],
    ["tmux installed", yesNo(result.tmux_installed)],
    ["Prepared", yesNo(result.prepared)],
    ["Linger", yesNo(result.linger)],
    ["Session running", yesNo(result.session_running)],
  ];
  return (
    <div className="rounded-lg border border-dark-600 bg-dark-900/40 px-4 py-3 space-y-2">
      <p className={`text-xs font-medium ${result.ok ? "text-rust-400" : "text-danger-400"}`}>
        {result.ok ? "Account is valid for the user terminal" : "Account is not valid for the user terminal"}
      </p>
      {result.reasons && result.reasons.length > 0 && (
        <ul className="list-disc ml-5 text-xs text-danger-400">
          {result.reasons.map((r) => <li key={r}>{r}</li>)}
        </ul>
      )}
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs font-mono">
        {rows.map(([k, v]) => (
          <div key={k} className="contents">
            <dt className="text-dark-400">{k}</dt>
            <dd className="text-dark-100 break-all">{v}</dd>
          </div>
        ))}
      </dl>
      {result.sudo_nopasswd && (
        <p className="text-xs text-warn-400 font-medium" role="alert">
          This user can run sudo without a password: a panel session alone gives root.
        </p>
      )}
    </div>
  );
}

function ProofDialog({
  title,
  confirmLabel,
  onCancel,
  onSubmit,
}: {
  title: string;
  confirmLabel: string;
  onCancel: () => void;
  onSubmit: (proof: Proof) => Promise<void>;
}) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<{ text: string; reasons?: string[] } | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) onCancel();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [busy, onCancel]);

  const go = async () => {
    setBusy(true);
    setError(null);
    try {
      await onSubmit({
        current_password: password || undefined,
        code: code || undefined,
      });
    } catch (e) {
      setError({ text: errorText(e, "Request failed"), reasons: reasonsOf(e) });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4"
      role="dialog"
      aria-modal="true"
      aria-label={title}
    >
      <form
        className="w-full max-w-sm rounded-lg border border-dark-500 bg-dark-800 p-5 space-y-3"
        onSubmit={(e) => { e.preventDefault(); void go(); }}
      >
        <h4 className="text-sm font-medium text-dark-100 break-all">{title}</h4>
        <p className="text-xs text-dark-300">Confirm with your password or a TOTP code.</p>
        <input
          type="password"
          autoComplete="current-password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Current password"
          aria-label="Current password"
          autoFocus
          className="w-full px-3 py-2 text-sm border border-dark-500 rounded-lg focus:ring-2 focus:ring-accent-500 outline-none bg-dark-700"
        />
        <input
          type="text"
          inputMode="text"
          autoCapitalize="none"
          autoComplete="one-time-code"
          value={code}
          onChange={(e) => setCode(e.target.value.replace(/[^0-9a-fA-F]/g, "").toLowerCase().slice(0, 16))}
          placeholder="TOTP or recovery code"
          aria-label="TOTP code or recovery code"
          className="w-full px-3 py-2 text-sm border border-dark-500 rounded-lg focus:ring-2 focus:ring-accent-500 outline-none bg-dark-700 font-mono"
        />
        {error && (
          <div className="text-xs text-danger-400" role="alert">
            <p>{error.text}</p>
            {error.reasons && error.reasons.length > 0 && (
              <ul className="list-disc ml-5 mt-1">
                {error.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
            )}
          </div>
        )}
        <div className="flex justify-end gap-2 pt-1">
          <button
            type="button"
            onClick={onCancel}
            disabled={busy}
            className="px-4 py-2 text-sm text-dark-200 hover:text-dark-100"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || (password === "" && code === "")}
            className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
          >
            {busy ? "Working..." : confirmLabel}
          </button>
        </div>
      </form>
    </div>
  );
}
