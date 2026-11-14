import { useState } from "react";
import { useAuth } from "../context/AuthContext";

// Shown on every page of every layout while an admin is logged in as another
// account. It is the only always-visible reminder that actions are being taken
// under someone else's identity, and the way back to the admin's own session.
export default function ImpersonationBanner() {
  const { user, stopImpersonation } = useAuth();
  const [leaving, setLeaving] = useState(false);

  if (!user?.impersonated_by) return null;

  const expires = user.impersonation_expires_at
    ? new Date(user.impersonation_expires_at * 1000).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
      })
    : null;

  const handleReturn = async () => {
    setLeaving(true);
    // stopImpersonation always ends in a full page navigation.
    await stopImpersonation();
  };

  return (
    // Opaque backing: the banner may be sticky over scrolling content.
    <div className="bg-dark-900">
    <div
      role="status"
      className="border-b border-warn-500/30 bg-warn-500/15 px-4 py-2 flex flex-wrap items-center justify-between gap-2"
    >
      <div className="flex items-center gap-2 min-w-0">
        <svg className="w-5 h-5 text-warn-400 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5} aria-hidden="true">
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 6a3.75 3.75 0 1 1-7.5 0 3.75 3.75 0 0 1 7.5 0ZM4.501 20.118a7.5 7.5 0 0 1 14.998 0A17.933 17.933 0 0 1 12 21.75c-2.676 0-5.216-.584-7.499-1.632Z" />
        </svg>
        <span className="text-sm text-warn-400 font-medium break-words">
          You are logged in as <span className="font-mono">{user.email}</span> (by{" "}
          <span className="font-mono">{user.impersonated_by.email}</span>)
          {expires && <> - expires at {expires}</>}
        </span>
      </div>
      <button
        onClick={handleReturn}
        disabled={leaving}
        className="px-3 py-1.5 bg-warn-500 text-dark-900 rounded text-xs font-bold hover:bg-warn-400 transition-colors disabled:opacity-50 flex items-center gap-1.5 shrink-0"
      >
        {leaving && <span className="w-3 h-3 border-2 border-dark-900/30 border-t-dark-900 rounded-full animate-spin" />}
        Return to my account
      </button>
    </div>
    </div>
  );
}
