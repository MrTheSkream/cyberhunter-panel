import { useCallback, useRef, useState } from "react";
import { api } from "../api";
import ConfirmDialog from "./ConfirmDialog";

/**
 * "Update source" card of Telemetry, Updates (feature 10, contract C-3).
 *
 * The GitHub token is write-only from here. It is read from an UNCONTROLLED
 * input through a ref, sent once, and the field is emptied as soon as the
 * request settles, success or not. It never enters React state, the parent,
 * a flash message or the console. The backend never sends it back either: the
 * card only learns `token_set`.
 *
 * No <form> element on purpose: a native submit of a password field is what
 * makes browsers offer to save it.
 */
export interface UpdateSourceInfo {
  repo?: string | null;
  token_set?: boolean;
  signing_key_id?: string | null;
}

export default function UpdateSourceCard({
  source,
  onChanged,
  onMessage,
}: {
  source: UpdateSourceInfo;
  /** Called after a save or clear (successful or not) to reload the status. */
  onChanged: () => Promise<void> | void;
  onMessage: (text: string, type: "success" | "error") => void;
}) {
  const tokenRef = useRef<HTMLInputElement>(null);
  // Only whether the field is non-empty, never its value.
  const [hasToken, setHasToken] = useState(false);
  const [repo, setRepo] = useState(source.repo ?? "");
  const [saving, setSaving] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [confirmClear, setConfirmClear] = useState(false);

  const emptyTokenField = () => {
    if (tokenRef.current) tokenRef.current.value = "";
    setHasToken(false);
  };

  const saveToken = async () => {
    const field = tokenRef.current;
    if (!field || !field.value.trim() || saving) return;
    const body: { token: string; repo?: string } = { token: field.value.trim() };
    const trimmedRepo = repo.trim();
    // No default literal here: without a repo the backend keeps its own value.
    if (trimmedRepo) body.repo = trimmedRepo;
    setSaving(true);
    try {
      await api.put("/update/source", body);
      onMessage("Update token saved.", "success");
    } catch (e: unknown) {
      onMessage(e instanceof Error ? e.message : "Could not save the token", "error");
    } finally {
      // Emptied once the response is in, whatever it said (contract C-3).
      emptyTokenField();
      setSaving(false);
    }
    await onChanged();
  };

  const clearToken = async () => {
    setConfirmClear(false);
    setClearing(true);
    try {
      await api.delete("/update/source/token");
      onMessage("Update token cleared.", "success");
    } catch (e: unknown) {
      onMessage(e instanceof Error ? e.message : "Could not clear the token", "error");
    } finally {
      setClearing(false);
    }
    await onChanged();
  };

  // Stable identity: ConfirmDialog refocuses Cancel whenever onCancel changes,
  // and the Updates tab re-renders on every status poll.
  const cancelClear = useCallback(() => setConfirmClear(false), []);

  return (
    <div className="bg-dark-800 border border-dark-600 rounded-lg p-4">
      <h3 className="text-sm font-medium text-dark-100 mb-3">Update source</h3>
      <div className="space-y-3">
        <div>
          <label htmlFor="update-source-repo" className="text-xs text-dark-400 mb-1 block">
            Release repository
          </label>
          <input
            id="update-source-repo"
            type="text"
            value={repo}
            onChange={e => setRepo(e.target.value)}
            placeholder="owner/name"
            autoComplete="off"
            spellCheck={false}
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-1.5 text-sm font-mono text-dark-200 placeholder:text-dark-500 focus:outline-none focus:border-rust-500"
          />
        </div>
        <div>
          <div className="flex items-center justify-between mb-1">
            <label htmlFor="update-source-token" className="text-xs text-dark-400">
              GitHub token
            </label>
            <span className={`text-xs ${source.token_set ? "text-rust-400" : "text-dark-400"}`}>
              {source.token_set ? "Token set" : "No token"}
            </span>
          </div>
          <input
            id="update-source-token"
            ref={tokenRef}
            type="password"
            autoComplete="off"
            spellCheck={false}
            placeholder="github_pat_..."
            defaultValue=""
            onChange={e => setHasToken(e.target.value.trim().length > 0)}
            onKeyDown={e => {
              if (e.key === "Enter") {
                e.preventDefault();
                void saveToken();
              }
            }}
            className="w-full bg-dark-900 border border-dark-600 rounded-lg px-3 py-1.5 text-sm font-mono text-dark-200 placeholder:text-dark-500 focus:outline-none focus:border-rust-500"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void saveToken()}
            disabled={saving || !hasToken}
            className="px-4 py-2 bg-rust-500 hover:bg-rust-600 text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
          >
            {saving ? "Saving..." : source.token_set ? "Replace token" : "Save token"}
          </button>
          {source.token_set && (
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              disabled={clearing}
              className="px-4 py-2 text-danger-400 hover:bg-danger-500/10 border border-danger-500/20 rounded-lg text-xs font-medium transition-colors disabled:opacity-50"
            >
              {clearing ? "Clearing..." : "Clear token"}
            </button>
          )}
        </div>
        <div className="pt-3 border-t border-dark-700 text-xs">
          {source.signing_key_id ? (
            <span className="text-dark-400">
              Signing key ID: <span className="font-mono text-dark-200">{source.signing_key_id}</span>
            </span>
          ) : (
            <span className="text-dark-400">No signing key in this build</span>
          )}
        </div>
      </div>
      {confirmClear && (
        <ConfirmDialog
          label="Clear the update token? Updates will be disabled until a new token is saved."
          confirmLabel="Clear token"
          tone="danger"
          onConfirm={() => void clearToken()}
          onCancel={cancelClear}
        />
      )}
    </div>
  );
}
