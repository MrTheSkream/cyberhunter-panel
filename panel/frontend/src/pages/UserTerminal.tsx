import { useCallback, useEffect, useRef, useState, type PointerEvent, type ReactNode } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { Terminal as XTerm, type ITheme } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { Unicode11Addon } from "@xterm/addon-unicode11";
import { WebglAddon } from "@xterm/addon-webgl";
import { ClipboardAddon, type IClipboardProvider } from "@xterm/addon-clipboard";
import "@xterm/xterm/css/xterm.css";
import { useAuth } from "../context/AuthContext";
import { setUserTerminalLinked } from "../data/navItems";

// ── /terminal/me: the user terminal ──
//
// A full-screen page outside the layout. It opens a shell as the Linux user
// linked to this panel account, attached to a persistent tmux session: closing
// the tab, losing the network or restarting the agent never ends the session,
// the page simply reattaches with a fresh single-use ticket.
//
// Never logged: the ticket, and anything typed or shown in the terminal.

const PAGE_PATH = "/terminal/me";
const LOGIN_URL = `/login?next=${encodeURIComponent(PAGE_PATH)}`;

// Same palette and font as Terminal.tsx, which does not export them (it must
// stay unchanged). Read from the same localStorage keys so both pages agree.
const themes: Record<string, ITheme> = {
  mocha: {
    background: "#1e1e2e",
    foreground: "#cdd6f4",
    cursor: "#f5e0dc",
    cursorAccent: "#1e1e2e",
    selectionBackground: "#585b7066",
    selectionInactiveBackground: "#585b7033",
    scrollbarSliderBackground: "#585b7099",
    scrollbarSliderHoverBackground: "#6c7086cc",
    scrollbarSliderActiveBackground: "#7f849c",
    black: "#45475a",
    red: "#f38ba8",
    green: "#a6e3a1",
    yellow: "#f9e2af",
    blue: "#89b4fa",
    magenta: "#f5c2e7",
    cyan: "#94e2d5",
    white: "#bac2de",
    brightBlack: "#585b70",
    brightRed: "#f38ba8",
    brightGreen: "#a6e3a1",
    brightYellow: "#f9e2af",
    brightBlue: "#89b4fa",
    brightMagenta: "#f5c2e7",
    brightCyan: "#94e2d5",
    brightWhite: "#a6adc8",
  },
  dracula: {
    background: "#282a36",
    foreground: "#f8f8f2",
    cursor: "#f8f8f2",
    cursorAccent: "#282a36",
    selectionBackground: "#44475a66",
    selectionInactiveBackground: "#44475a33",
    scrollbarSliderBackground: "#6272a499",
    scrollbarSliderHoverBackground: "#6272a4cc",
    scrollbarSliderActiveBackground: "#7b8cc4",
    black: "#21222c",
    red: "#ff5555",
    green: "#50fa7b",
    yellow: "#f1fa8c",
    blue: "#bd93f9",
    magenta: "#ff79c6",
    cyan: "#8be9fd",
    white: "#f8f8f2",
    brightBlack: "#6272a4",
    brightRed: "#ff6e6e",
    brightGreen: "#69ff94",
    brightYellow: "#ffffa5",
    brightBlue: "#d6acff",
    brightMagenta: "#ff92df",
    brightCyan: "#a4ffff",
    brightWhite: "#ffffff",
  },
  light: {
    background: "#fafafa",
    foreground: "#383a42",
    cursor: "#526fff",
    cursorAccent: "#fafafa",
    selectionBackground: "#d0d0d066",
    selectionInactiveBackground: "#d0d0d033",
    scrollbarSliderBackground: "#a0a1a799",
    scrollbarSliderHoverBackground: "#8a8b91cc",
    scrollbarSliderActiveBackground: "#696c77",
    black: "#383a42",
    red: "#e45649",
    green: "#50a14f",
    yellow: "#c18401",
    blue: "#4078f2",
    magenta: "#a626a4",
    cyan: "#0184bc",
    white: "#a0a1a7",
    brightBlack: "#696c77",
    brightRed: "#e45649",
    brightGreen: "#50a14f",
    brightYellow: "#c18401",
    brightBlue: "#4078f2",
    brightMagenta: "#a626a4",
    brightCyan: "#0184bc",
    brightWhite: "#383a42",
  },
};

const FONT_FAMILY =
  "'JetBrains Mono', ui-monospace, 'Cascadia Code', 'Source Code Pro', Menlo, monospace";
const FONT_MIN = 10;
const FONT_MAX = 24;

function readFontSize(): number {
  try {
    const stored = parseInt(localStorage.getItem("dp-terminal-font") || "", 10);
    if (Number.isFinite(stored)) return Math.max(FONT_MIN, Math.min(FONT_MAX, stored));
  } catch {
    /* storage unavailable */
  }
  return window.innerWidth < 768 ? 11 : 14;
}

function readTheme(): ITheme {
  try {
    return themes[localStorage.getItem("dp-terminal-theme") || "mocha"] || themes.mocha;
  } catch {
    return themes.mocha;
  }
}

// ── Requests ──
// Plain fetch rather than api.ts: a 401 there navigates to a bare /login and
// would lose the way back here. No X-Server-Id either: the user terminal only
// exists on the local server, which is where /agent/terminal/ws leads.

type JsonResult<T> =
  | { ok: true; data: T }
  | { ok: false; status: number; code?: string; error: string };

async function getJson<T>(path: string): Promise<JsonResult<T>> {
  try {
    const res = await fetch(`/api${path}`, {
      credentials: "same-origin",
      headers: { "X-Requested-With": "DockPanel" },
    });
    const data = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (res.ok) return { ok: true, data: data as T };
    return {
      ok: false,
      status: res.status,
      code: typeof data.code === "string" ? data.code : undefined,
      error: typeof data.error === "string" ? data.error : `Request failed (${res.status})`,
    };
  } catch {
    return { ok: false, status: 0, error: "The panel is not reachable" };
  }
}

function isMfaRequired(code?: string | null, text?: string | null): boolean {
  if (code === "mfa_required") return true;
  return !!text && /mfa_required|two-factor/i.test(text);
}

// ── Input framing ──
// A paste arrives as one onData call. It is cut into frames of at most 16 KiB
// of JSON, counting each code point at its escaped UTF-8 size, so a frame never
// splits a surrogate pair and always stays under the agent's 64 KiB limit.

const FRAME_LIMIT = 16 * 1024;
const FRAME_OVERHEAD = JSON.stringify({ type: "input", data: "" }).length;

function jsonCost(ch: string): number {
  const c = ch.codePointAt(0) ?? 0;
  if (c === 0x22 || c === 0x5c) return 2;
  if (c < 0x20) return c === 8 || c === 9 || c === 10 || c === 12 || c === 13 ? 2 : 6;
  if (c < 0x80) return 1;
  if (c < 0x800) return 2;
  if (c >= 0xd800 && c <= 0xdfff) return 6; // lone surrogate, escaped by JSON.stringify
  if (c < 0x10000) return 3;
  return 4;
}

export function chunkInput(data: string): string[] {
  const budget = FRAME_LIMIT - FRAME_OVERHEAD;
  if (data.length * 6 <= budget) return [data];
  const out: string[] = [];
  let cur = "";
  let size = 0;
  for (const ch of data) {
    const cost = jsonCost(ch);
    if (size + cost > budget) {
      out.push(cur);
      cur = "";
      size = 0;
    }
    cur += ch;
    size += cost;
  }
  if (cur) out.push(cur);
  return out;
}

// Sticky Ctrl from the mobile key bar: the next typed character becomes its
// control code, the way a terminal keyboard does it.
function applyCtrl(data: string): string {
  if (data.length !== 1) return data;
  const c = data.charCodeAt(0);
  if (c >= 0x61 && c <= 0x7a) return String.fromCharCode(c - 0x60); // a-z
  if (c >= 0x40 && c <= 0x5f) return String.fromCharCode(c & 0x1f); // @ A-Z [ \ ] ^ _
  if (c === 0x20) return "\x00";
  if (c === 0x3f) return "\x7f";
  return data;
}

// OSC 52: a program in the session may WRITE the browser clipboard (tmux copy
// mode does), never read it. A read request always gets an empty answer.
function writeClipboard(text: string): void {
  try {
    void navigator.clipboard?.writeText(text).catch(() => {});
  } catch {
    /* clipboard API unavailable */
  }
}

const clipboardProvider: IClipboardProvider = {
  readText: () => "",
  writeText: (_selection, text) => writeClipboard(text),
};

// ── Viewport ──
// The visual viewport is what is left above a mobile keyboard. iOS does not
// shrink the layout viewport, so the page sizes itself from this.

function readViewport() {
  const vv = window.visualViewport;
  return vv ? { height: vv.height, top: vv.offsetTop } : { height: window.innerHeight, top: 0 };
}

function useViewportBox() {
  const [box, setBox] = useState(readViewport);
  useEffect(() => {
    const vv = window.visualViewport;
    const update = () => setBox(readViewport());
    vv?.addEventListener("resize", update);
    vv?.addEventListener("scroll", update);
    window.addEventListener("resize", update);
    return () => {
      vv?.removeEventListener("resize", update);
      vv?.removeEventListener("scroll", update);
      window.removeEventListener("resize", update);
    };
  }, []);
  return box;
}

function useIsTouch(): boolean {
  const query = "(pointer: coarse), (max-width: 767px)";
  const [touch, setTouch] = useState(() => window.matchMedia?.(query).matches ?? false);
  useEffect(() => {
    const mq = window.matchMedia?.(query);
    if (!mq) return;
    const on = () => setTouch(mq.matches);
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return touch;
}

// ── Page ──

type Gate =
  | { kind: "loading" }
  | { kind: "ready"; login: string }
  | { kind: "unavailable"; reason: string }
  | { kind: "mfa" };

interface MeResponse {
  linked: boolean;
  login: string | null;
  available: boolean;
  reason: string | null;
  code?: string | null;
}

export default function UserTerminal() {
  const { user, loading } = useAuth();
  const [gate, setGate] = useState<Gate>({ kind: "loading" });

  useEffect(() => {
    if (loading || !user) return;
    let cancelled = false;
    void (async () => {
      const r = await getJson<MeResponse>("/terminal/user/me");
      if (cancelled) return;
      if (!r.ok) {
        if (r.status === 401) {
          window.location.replace(LOGIN_URL);
          return;
        }
        setGate(isMfaRequired(r.code, r.error) ? { kind: "mfa" } : { kind: "unavailable", reason: r.error });
        return;
      }
      const me = r.data;
      setUserTerminalLinked(me.linked === true);
      if (!me.linked || !me.login) {
        setGate({ kind: "unavailable", reason: me.reason || "No Linux account is linked to your panel account" });
      } else if (!me.available) {
        setGate(
          isMfaRequired(me.code, me.reason)
            ? { kind: "mfa" }
            : { kind: "unavailable", reason: me.reason || "The user terminal is not available" },
        );
      } else {
        setGate({ kind: "ready", login: me.login });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [loading, user]);

  if (loading) return <FullScreenSpinner />;
  if (!user) return <Navigate to={LOGIN_URL} replace />;
  if (gate.kind === "loading") return <FullScreenSpinner />;
  if (gate.kind === "mfa") return <MfaScreen />;
  if (gate.kind === "unavailable") return <UnavailableScreen reason={gate.reason} />;
  return (
    <TerminalView
      login={gate.login}
      onMfaRequired={() => setGate({ kind: "mfa" })}
    />
  );
}

function FullScreenSpinner() {
  return (
    <div className="fixed inset-0 flex items-center justify-center bg-dark-900">
      <div className="w-6 h-6 border-2 border-dark-600 border-t-rust-500 rounded-full animate-spin" />
    </div>
  );
}

function ScreenFrame({ title, children }: { title: string; children: ReactNode }) {
  return (
    <main className="fixed inset-0 flex items-center justify-center bg-dark-900 px-4">
      <div className="w-full max-w-md rounded-lg border border-dark-500 bg-dark-800 p-6 space-y-4">
        <h1 className="text-sm font-medium text-dark-100 uppercase font-mono tracking-widest">{title}</h1>
        {children}
      </div>
    </main>
  );
}

function UnavailableScreen({ reason }: { reason: string }) {
  return (
    <ScreenFrame title="My session">
      <p className="text-sm text-dark-200">{reason}</p>
      <div className="flex gap-2">
        <a href="/" className="px-4 py-2 bg-dark-700 text-dark-100 border border-dark-500 rounded-lg text-sm font-medium hover:border-dark-400">
          Back to panel
        </a>
        <button
          onClick={() => window.location.reload()}
          className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600"
        >
          Try again
        </button>
      </div>
    </ScreenFrame>
  );
}

function MfaScreen() {
  const [busy, setBusy] = useState(false);
  const signInAgain = async () => {
    setBusy(true);
    try {
      await fetch("/api/auth/logout", {
        method: "POST",
        credentials: "same-origin",
        headers: { "X-Requested-With": "DockPanel" },
      });
    } catch {
      /* the redirect below still lands on the sign-in page */
    }
    try {
      localStorage.removeItem("dp-active-server");
    } catch {
      /* storage unavailable */
    }
    window.location.replace(LOGIN_URL);
  };
  return (
    <ScreenFrame title="My session">
      <p className="text-sm text-dark-100">Sign in again with two-factor authentication</p>
      <p className="text-xs text-dark-300">
        The user terminal requires a session opened with a TOTP code or a passkey. This session was opened without one.
      </p>
      <div className="flex gap-2">
        <button
          onClick={signInAgain}
          disabled={busy}
          className="px-4 py-2 bg-rust-500 text-white rounded-lg text-sm font-medium hover:bg-rust-600 disabled:opacity-50"
        >
          {busy ? "Signing out..." : "Sign in again"}
        </button>
        <a href="/" className="px-4 py-2 bg-dark-700 text-dark-100 border border-dark-500 rounded-lg text-sm font-medium hover:border-dark-400">
          Back to panel
        </a>
      </div>
    </ScreenFrame>
  );
}

// ── Terminal ──

type ConnState =
  | { kind: "connecting" }
  | { kind: "connected" }
  | { kind: "reconnecting"; reason?: string; retryAt: number }
  | { kind: "detached" }
  | { kind: "stopped"; reason: string };

type CtrlMode = "off" | "once" | "locked";

const RECONNECT_FIRST_MS = 1000;
const RECONNECT_MAX_MS = 30000;
// A connection that stayed up this long resets the backoff when it drops.
const STABLE_MS = 10000;
// Close code the agent sends when tmux detached or the shell exited: the
// session ended on purpose, so the page stops instead of reattaching.
const CLOSE_DETACHED = 4000;
// Handshakes refused in a row (the socket never opened) before the page stops
// retrying. Five survives an agent restart with the backoff above (~30 s).
const MAX_HANDSHAKE_FAILURES = 5;
const HANDSHAKE_REFUSED =
  "The server refused the terminal connection several times. Likely causes: the Linux account is not " +
  "prepared (save the link again in Settings), the Origin check (the panel vhost must send " +
  "\"Host $http_host\" on /agent/terminal/ws), the Linux account is no longer valid, or too many " +
  "connections are open for this account.";

function TerminalView({ login, onMfaRequired }: { login: string; onMfaRequired: () => void }) {
  const navigate = useNavigate();
  const box = useViewportBox();
  const isTouch = useIsTouch();
  const hostRef = useRef<HTMLDivElement>(null);
  const termRef = useRef<XTerm | null>(null);
  const fitRef = useRef<() => void>(() => {});
  const sendRef = useRef<(data: string) => void>(() => {});
  const reconnectRef = useRef<() => void>(() => {});
  const ctrlRef = useRef<CtrlMode>("off");
  const onMfaRef = useRef(onMfaRequired);
  onMfaRef.current = onMfaRequired;

  const [conn, setConn] = useState<ConnState>({ kind: "connecting" });
  const [reattached, setReattached] = useState(false);
  const [notice, setNotice] = useState("");
  const [fontSize, setFontSize] = useState(readFontSize);
  const [ctrlMode, setCtrlModeState] = useState<CtrlMode>("off");
  const [now, setNow] = useState(() => Date.now());
  const theme = useState(readTheme)[0];

  const setCtrlMode = useCallback((m: CtrlMode) => {
    ctrlRef.current = m;
    setCtrlModeState(m);
  }, []);

  const flash = useCallback((text: string) => {
    setNotice(text);
    window.setTimeout(() => setNotice((cur) => (cur === text ? "" : cur)), 3000);
  }, []);

  // ── Terminal and connection lifecycle: one xterm for the page's life ──
  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    let disposed = false;
    let ws: WebSocket | null = null;
    let retryTimer: number | undefined;
    let reattachTimer: number | undefined;
    let attempt = 0;
    let everConnected = false;
    let openedAt = 0;
    // Consecutive sockets that closed without ever opening (refused handshake).
    let handshakeFailures = 0;
    let lastSent = { cols: 0, rows: 0 };
    let fitFrame = 0;
    // Bumped by every connect(): an older attempt still awaiting its ticket
    // gives up instead of opening a second socket.
    let generation = 0;

    const term = new XTerm({
      allowProposedApi: true,
      cursorBlink: true,
      fontSize: readFontSize(),
      fontFamily: FONT_FAMILY,
      lineHeight: 1.2,
      scrollback: 10000,
      minimumContrastRatio: 4.5,
      theme: readTheme(),
    });
    termRef.current = term;
    const fit = new FitAddon();
    term.loadAddon(fit);
    term.loadAddon(new Unicode11Addon());
    term.unicode.activeVersion = "11";
    term.loadAddon(new ClipboardAddon(undefined, clipboardProvider));

    const doFit = () => {
      if (disposed || !host.clientWidth || !host.clientHeight) return;
      try {
        fit.fit();
      } catch {
        /* not measurable yet */
      }
    };
    const scheduleFit = () => {
      if (fitFrame) cancelAnimationFrame(fitFrame);
      fitFrame = requestAnimationFrame(() => {
        fitFrame = 0;
        doFit();
      });
    };
    fitRef.current = scheduleFit;

    const sendFrame = (frame: object) => {
      if (ws && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify(frame));
        } catch {
          /* socket closing: onclose reconnects */
        }
      }
    };
    const sendInput = (data: string) => {
      if (!data) return;
      for (const chunk of chunkInput(data)) sendFrame({ type: "input", data: chunk });
    };
    sendRef.current = sendInput;

    const sendResize = (cols: number, rows: number) => {
      if (!ws || ws.readyState !== WebSocket.OPEN) return;
      if (cols === lastSent.cols && rows === lastSent.rows) return;
      lastSent = { cols, rows };
      sendFrame({ type: "resize", cols, rows });
    };

    term.onData((data) => {
      let d = data;
      if (ctrlRef.current !== "off" && d.length === 1) {
        d = applyCtrl(d);
        if (ctrlRef.current === "once") {
          ctrlRef.current = "off";
          setCtrlModeState("off");
        }
      }
      sendInput(d);
    });
    term.onResize(({ cols, rows }) => sendResize(cols, rows));

    // Only Ctrl+Shift+C, Ctrl+Shift+V and Ctrl+V are kept by the page.
    // Everything else, Ctrl+C, D, R, L and Z included, goes to the shell.
    term.attachCustomKeyEventHandler((e) => {
      if (!e.ctrlKey || e.altKey || e.metaKey) return true;
      const key = e.key.toLowerCase();
      if (e.shiftKey && (key === "c" || e.code === "KeyC")) {
        if (e.type === "keydown") {
          e.preventDefault();
          const sel = term.getSelection();
          if (sel) writeClipboard(sel);
        }
        return false;
      }
      if (key === "v" || e.code === "KeyV") {
        // No preventDefault: the browser then fires a paste event, handled
        // below, without asking for clipboard read permission.
        return false;
      }
      return true;
    });

    // Every paste goes through term.paste(): bracketed when the program asked
    // for it (tmux and Claude do), then framed by sendInput.
    const onPaste = (e: ClipboardEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const text = e.clipboardData?.getData("text/plain") ?? "";
      if (text) term.paste(text);
    };
    host.addEventListener("paste", onPaste, true);

    const onContextMenu = (e: MouseEvent) => {
      // Shift + right click keeps the browser menu.
      if (e.shiftKey) return;
      e.preventDefault();
      void navigator.clipboard
        ?.readText()
        .then((t) => {
          if (t && !disposed) term.paste(t);
        })
        .catch(() => flash("Clipboard access denied. Use Ctrl+V to paste."));
    };
    host.addEventListener("contextmenu", onContextMenu);

    const resizeObserver = new ResizeObserver(scheduleFit);
    resizeObserver.observe(host);

    const clearRetry = () => {
      if (retryTimer !== undefined) window.clearTimeout(retryTimer);
      retryTimer = undefined;
    };

    const scheduleRetry = (reason?: string) => {
      if (disposed) return;
      clearRetry();
      const base = Math.min(RECONNECT_MAX_MS, RECONNECT_FIRST_MS * 2 ** attempt);
      const delay = Math.min(RECONNECT_MAX_MS, Math.round(base * (1 + Math.random() * 0.25)));
      attempt += 1;
      setConn({ kind: "reconnecting", reason, retryAt: Date.now() + delay });
      retryTimer = window.setTimeout(() => void connect(), delay);
    };

    // The browser hides the handshake status (412, 403, 409...): ask the panel
    // for a reason, and stop after several refusals in a row.
    const onHandshakeRefused = async (mine: number) => {
      handshakeFailures += 1;
      const r = await getJson<MeResponse>("/terminal/user/me");
      if (disposed || mine !== generation) return;
      let reason: string | undefined;
      if (!r.ok) {
        if (r.status === 401) {
          window.location.replace(LOGIN_URL);
          return;
        }
        if (isMfaRequired(r.code, r.error)) {
          onMfaRef.current();
          return;
        }
        reason = r.error;
      } else if (!r.data.linked || !r.data.login) {
        setConn({ kind: "stopped", reason: r.data.reason || "No Linux account is linked to your panel account" });
        return;
      } else if (!r.data.available) {
        if (isMfaRequired(r.data.code, r.data.reason)) {
          onMfaRef.current();
          return;
        }
        setConn({ kind: "stopped", reason: r.data.reason || "The user terminal is not available" });
        return;
      }
      if (handshakeFailures >= MAX_HANDSHAKE_FAILURES) {
        setConn({ kind: "stopped", reason: HANDSHAKE_REFUSED });
        return;
      }
      scheduleRetry(reason ?? "(the server refused the connection)");
    };

    const connect = async () => {
      if (disposed) return;
      clearRetry();
      const mine = ++generation;
      if (!everConnected) setConn({ kind: "connecting" });
      else setConn((c) => (c.kind === "reconnecting" ? c : { kind: "reconnecting", retryAt: Date.now() }));

      // A new single-use ticket for every attempt.
      const r = await getJson<{ token: string; login?: string }>("/terminal/user/token");
      if (disposed || mine !== generation) return;
      if (!r.ok) {
        if (r.status === 401 && r.code === "session_invalid") {
          window.location.replace(LOGIN_URL);
          return;
        }
        if (isMfaRequired(r.code, r.error)) {
          onMfaRef.current();
          return;
        }
        if (r.status === 401 || r.status === 403 || r.status === 404) {
          setConn({ kind: "stopped", reason: r.error });
          return;
        }
        scheduleRetry(r.error);
        return;
      }

      doFit();
      const cols = term.cols;
      const rows = term.rows;
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      const url =
        `${proto}//${window.location.host}/agent/terminal/ws` +
        `?token=${encodeURIComponent(r.data.token)}&cols=${cols}&rows=${rows}`;

      let sock: WebSocket;
      try {
        sock = new WebSocket(url);
      } catch {
        scheduleRetry("Connection failed");
        return;
      }
      sock.binaryType = "arraybuffer";
      ws = sock;
      // One streaming decoder per connection: a binary frame ending inside a
      // multi-byte character keeps its first bytes for the next frame.
      const decoder = new TextDecoder("utf-8");

      sock.onopen = () => {
        if (disposed || ws !== sock) return;
        openedAt = Date.now();
        lastSent = { cols, rows };
        if (everConnected) {
          // tmux redraws the whole screen on attach.
          term.reset();
          setReattached(true);
          if (reattachTimer !== undefined) window.clearTimeout(reattachTimer);
          reattachTimer = window.setTimeout(() => setReattached(false), 2000);
        }
        everConnected = true;
        setConn({ kind: "connected" });
        // The grid may have changed while the socket was opening.
        sendResize(term.cols, term.rows);
      };
      sock.onmessage = (ev) => {
        if (ws !== sock) return;
        if (typeof ev.data === "string") term.write(ev.data);
        else if (ev.data instanceof ArrayBuffer) term.write(decoder.decode(new Uint8Array(ev.data), { stream: true }));
      };
      sock.onclose = (ev: CloseEvent) => {
        if (ws !== sock) return;
        ws = null;
        if (disposed) return;
        const opened = openedAt !== 0;
        if (opened && Date.now() - openedAt >= STABLE_MS) attempt = 0;
        openedAt = 0;
        if (ev.code === CLOSE_DETACHED) {
          // tmux detach or shell exit: no automatic reattach.
          clearRetry();
          attempt = 0;
          handshakeFailures = 0;
          setConn({ kind: "detached" });
          return;
        }
        if (opened) {
          // A lost connection: reconnect without end.
          handshakeFailures = 0;
          scheduleRetry();
          return;
        }
        void onHandshakeRefused(mine);
      };
    };

    reconnectRef.current = () => {
      attempt = 0;
      handshakeFailures = 0;
      clearRetry();
      const old = ws;
      ws = null;
      if (old) {
        try {
          old.close();
        } catch {
          /* already closed */
        }
      }
      void connect();
    };

    // Start once the webfont is in: xterm measures cells at open time.
    void (async () => {
      try {
        await document.fonts?.ready;
      } catch {
        /* a font failure must not stop the terminal */
      }
      if (disposed) return;
      term.open(host);
      try {
        const webgl = new WebglAddon();
        webgl.onContextLoss(() => webgl.dispose()); // back to the DOM renderer
        term.loadAddon(webgl);
      } catch {
        /* no WebGL: the DOM renderer stays */
      }
      doFit();
      term.focus();
      void connect();
    })();

    return () => {
      disposed = true;
      clearRetry();
      if (reattachTimer !== undefined) window.clearTimeout(reattachTimer);
      if (fitFrame) cancelAnimationFrame(fitFrame);
      resizeObserver.disconnect();
      host.removeEventListener("paste", onPaste, true);
      host.removeEventListener("contextmenu", onContextMenu);
      const old = ws;
      ws = null;
      if (old) {
        try {
          old.close();
        } catch {
          /* already closed */
        }
      }
      sendRef.current = () => {};
      reconnectRef.current = () => {};
      fitRef.current = () => {};
      termRef.current = null;
      term.dispose();
    };
  }, [flash]);

  // Font size: persisted with the same key as Terminal.tsx.
  useEffect(() => {
    try {
      localStorage.setItem("dp-terminal-font", String(fontSize));
    } catch {
      /* storage unavailable */
    }
    const term = termRef.current;
    if (term && term.options.fontSize !== fontSize) {
      term.options.fontSize = fontSize;
      fitRef.current();
    }
  }, [fontSize]);

  // Visual viewport changes (mobile keyboard) resize the page box; refit.
  useEffect(() => {
    fitRef.current();
  }, [box.height, box.top, isTouch]);

  // Countdown for the "Reconnecting" banner.
  useEffect(() => {
    if (conn.kind !== "reconnecting") return;
    const t = window.setInterval(() => setNow(Date.now()), 500);
    return () => window.clearInterval(t);
  }, [conn.kind]);

  const focusTerm = () => termRef.current?.focus();

  const copySelection = () => {
    const sel = termRef.current?.getSelection() ?? "";
    if (!sel) {
      flash("Nothing selected. Shift + drag selects text.");
    } else if (!navigator.clipboard) {
      flash("Clipboard is not available on this page");
    } else {
      navigator.clipboard.writeText(sel).then(
        () => flash("Copied"),
        () => flash("Clipboard access denied"),
      );
    }
    focusTerm();
  };

  const pasteClipboard = () => {
    const term = termRef.current;
    if (!term) return;
    if (!navigator.clipboard?.readText) {
      flash("Clipboard is not available. Use Ctrl+V to paste.");
      return;
    }
    navigator.clipboard.readText().then(
      (t) => {
        if (t) term.paste(t);
        term.focus();
      },
      () => flash("Clipboard access denied. Use Ctrl+V to paste."),
    );
  };

  const sendKey = (data: string) => {
    sendRef.current(data);
    focusTerm();
  };

  const cycleCtrl = () => {
    setCtrlMode(ctrlMode === "off" ? "once" : ctrlMode === "once" ? "locked" : "off");
    focusTerm();
  };

  const statusText = (() => {
    switch (conn.kind) {
      case "connecting":
        return "Connecting…";
      case "connected":
        return `Connected as ${login}`;
      case "reconnecting": {
        const s = Math.max(0, Math.ceil((conn.retryAt - now) / 1000));
        return s > 0 ? `Reconnecting in ${s}s…` : "Reconnecting…";
      }
      case "detached":
        return "Session detached";
      default:
        return "Disconnected";
    }
  })();
  const dotClass =
    conn.kind === "connected"
      ? "bg-rust-500"
      : conn.kind === "stopped"
        ? "bg-danger-500"
        : conn.kind === "detached"
          ? "bg-dark-400"
          : "bg-warn-500 animate-pulse";

  const barButton =
    "px-2 py-1 text-xs font-mono text-dark-200 hover:text-dark-100 hover:bg-dark-700 rounded touch-manipulation";
  // Keeps the soft keyboard open: the button never takes focus from xterm.
  const keepFocus = (e: PointerEvent<HTMLButtonElement>) => e.preventDefault();

  return (
    <div
      className="fixed left-0 right-0 flex flex-col bg-dark-900 overflow-hidden"
      style={{ top: box.top, height: box.height }}
    >
      {/* Thin bar */}
      <div className="flex items-center gap-1 px-2 py-1 border-b border-dark-600 bg-dark-800 shrink-0 min-w-0">
        <span className={`w-2 h-2 rounded-full shrink-0 ${dotClass}`} aria-hidden="true" />
        <span className="text-xs font-mono text-dark-200 truncate min-w-0 flex-1" role="status" aria-live="polite">
          {statusText}
        </span>
        <button onPointerDown={keepFocus} onClick={copySelection} className={barButton} title="Copy selection (Ctrl+Shift+C)">
          Copy
        </button>
        <button onPointerDown={keepFocus} onClick={pasteClipboard} className={barButton} title="Paste (Ctrl+V)">
          Paste
        </button>
        <button
          onPointerDown={keepFocus}
          onClick={() => setFontSize((s) => Math.max(FONT_MIN, s - 1))}
          className={barButton}
          aria-label="Smaller font"
        >
          A-
        </button>
        <span className="text-xs font-mono text-dark-400 w-5 text-center hidden sm:inline">{fontSize}</span>
        <button
          onPointerDown={keepFocus}
          onClick={() => setFontSize((s) => Math.min(FONT_MAX, s + 1))}
          className={barButton}
          aria-label="Larger font"
        >
          A+
        </button>
        <button
          onPointerDown={keepFocus}
          onClick={() => { reconnectRef.current(); focusTerm(); }}
          className={barButton}
          title="Reattach now"
        >
          Reconnect
        </button>
        <button onClick={() => navigate("/")} className={barButton} title="Back to the panel. The session keeps running.">
          Exit
        </button>
      </div>

      {/* Terminal */}
      <div className="relative flex-1 min-h-0" style={{ backgroundColor: theme.background }}>
        {(conn.kind === "reconnecting" || reattached || conn.kind === "stopped" || conn.kind === "detached" || notice) && (
          <div className="absolute top-2 left-1/2 -translate-x-1/2 z-10 max-w-[90%] pointer-events-none">
            {conn.kind === "stopped" ? (
              <div className="pointer-events-auto rounded-lg border border-danger-500/40 bg-dark-800/95 px-3 py-2 text-xs font-mono text-danger-400 flex flex-wrap items-center gap-2">
                <span className="min-w-0">{conn.reason}</span>
                <button
                  onClick={() => { reconnectRef.current(); focusTerm(); }}
                  className="shrink-0 px-2 py-0.5 rounded border border-danger-500/40 text-dark-100 hover:bg-dark-700"
                >
                  Retry
                </button>
              </div>
            ) : conn.kind === "detached" ? (
              <div className="pointer-events-auto rounded-lg border border-dark-500 bg-dark-800/95 px-3 py-2 text-xs font-mono text-dark-100 flex flex-wrap items-center gap-2">
                <span>Session detached</span>
                <button
                  onClick={() => { reconnectRef.current(); focusTerm(); }}
                  className="shrink-0 px-2 py-0.5 rounded border border-dark-500 text-dark-100 hover:bg-dark-700"
                >
                  Reconnect
                </button>
              </div>
            ) : conn.kind === "reconnecting" ? (
              <div className="rounded-lg border border-warn-500/40 bg-dark-800/95 px-3 py-2 text-xs font-mono text-warn-400">
                Reconnecting…{conn.reason ? ` ${conn.reason}` : ""}
              </div>
            ) : reattached ? (
              <div className="rounded-lg border border-rust-500/40 bg-dark-800/95 px-3 py-2 text-xs font-mono text-rust-400">
                Reattached
              </div>
            ) : (
              <div className="rounded-lg border border-dark-500 bg-dark-800/95 px-3 py-2 text-xs font-mono text-dark-200">
                {notice}
              </div>
            )}
          </div>
        )}
        {/* Padding on a wrapper: FitAddon measures the host's own box. */}
        <div className="absolute inset-0 px-1 pt-1">
          <div ref={hostRef} className="w-full h-full" />
        </div>
      </div>

      {/* Mobile key bar */}
      {isTouch && (
        <div className="grid grid-cols-10 gap-1 px-1.5 py-1.5 border-t border-dark-500 bg-dark-800 shrink-0">
          {[
            { label: "Esc", data: "\x1b" },
            { label: "Tab", data: "\t" },
          ].map((k) => (
            <MobileKey key={k.label} label={k.label} onPress={() => sendKey(k.data)} />
          ))}
          <MobileKey
            label={ctrlMode === "locked" ? "CTRL" : "Ctrl"}
            active={ctrlMode !== "off"}
            onPress={cycleCtrl}
            title="Tap: next key only. Tap again: locked. Third tap: off."
          />
          {[
            { label: "←", data: "\x1b[D" },
            { label: "↑", data: "\x1b[A" },
            { label: "↓", data: "\x1b[B" },
            { label: "→", data: "\x1b[C" },
            { label: "^B", data: "\x02", title: "Ctrl+B, the tmux prefix" },
          ].map((k) => (
            <MobileKey key={k.label} label={k.label} title={k.title} onPress={() => sendKey(k.data)} />
          ))}
          <div className="col-span-2">
            <MobileKey label="Paste" onPress={pasteClipboard} />
          </div>
        </div>
      )}
    </div>
  );
}

function MobileKey({
  label,
  onPress,
  active = false,
  title,
}: {
  label: string;
  onPress: () => void;
  active?: boolean;
  title?: string;
}) {
  return (
    <button
      type="button"
      title={title}
      onPointerDown={(e) => e.preventDefault()}
      onMouseDown={(e) => e.preventDefault()}
      onClick={onPress}
      className={`w-full py-2 rounded text-[11px] font-mono font-medium touch-manipulation text-center ${
        active ? "bg-rust-500 text-white" : "bg-dark-700 text-dark-200 active:bg-dark-500"
      }`}
    >
      {label}
    </button>
  );
}
