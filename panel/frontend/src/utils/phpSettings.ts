/**
 * Per-site PHP settings and global php.ini - shapes and pure helpers.
 *
 * Contract: conception/02-php-contrats.md, sections A2/A3 and B1–B3. Nothing in
 * here imports React or the API client, so every helper can be exercised on its
 * own.
 */

export type PhpPm = "ondemand" | "dynamic" | "static";

export interface PhpPool {
  pm: PhpPm;
  max_children: number;
  max_requests: number;
  idle_timeout_s: number;
  request_terminate_timeout_s: number;
}

export interface PhpField {
  key: string;
  label: string;
  /** size = "256M" ; bool = "On"/"Off". */
  kind: "size" | "int" | "bool" | "choice";
  /** size: in MB ; int: raw value. */
  min?: number;
  max?: number;
  choices?: { value: string; label: string }[];
}

/** `GET /api/sites/{id}/php-settings` (B1). */
export interface PhpSettingsResponse {
  php_version: string | null;
  /** The caller may change isolation, pool and extra directives. */
  can_admin: boolean;
  /**
   * Site migrated from before per-site PHP settings (C bis): only memory_limit
   * and the overridden keys are applied, the rest comes from the global php.ini.
   */
  legacy?: boolean;
  /** Keys taken from the global php.ini (legacy sites only; absent from `defaults`/`effective`). */
  inherits_global?: string[];
  /** The site's own overrides. */
  values: Record<string, string>;
  /** What is applied (overrides + defaults). */
  effective: Record<string, string>;
  defaults: Record<string, string>;
  /** The settings, in display order. */
  fields: PhpField[];
  isolation: boolean;
  disable_shell: boolean;
  pool: PhpPool;
  extra: [string, string][];
}

/** `PUT /api/sites/{id}/php-settings` body (B2). Owners may send `values` only. */
export interface PhpSettingsUpdate {
  /** null = back to the default. */
  values?: Record<string, string | null>;
  isolation?: boolean;
  disable_shell?: boolean;
  pool?: Partial<PhpPool>;
  extra?: [string, string][];
  /** Admin only: `false` = switch a legacy site to the panel defaults (C bis). */
  legacy?: false;
}

/** pm.max_children bound enforced by the API (same as Resource Limits). */
export const POOL_MAX_CHILDREN = 100;

/** `GET /api/php/ini/{version}` (A2/B3). */
export interface PhpIniResponse {
  version: string;
  path: string;
  content: string;
  values: Record<string, string | null>;
}

/** The 8 keys of the global php.ini form (A2), in display order. */
export const PHP_INI_KEYS: { key: string; label: string; hint: string }[] = [
  { key: "memory_limit", label: "Memory limit", hint: "e.g. 128M, -1 = unlimited" },
  { key: "max_execution_time", label: "Max execution time (s)", hint: "e.g. 30, 0 = unlimited" },
  { key: "max_input_time", label: "Max input time (s)", hint: "e.g. 60, -1 = same as execution" },
  { key: "upload_max_filesize", label: "Upload max filesize", hint: "e.g. 2M" },
  { key: "post_max_size", label: "Post max size", hint: "e.g. 8M" },
  { key: "display_errors", label: "Display errors", hint: "On / Off" },
  { key: "error_reporting", label: "Error reporting", hint: "e.g. E_ALL & ~E_DEPRECATED & ~E_STRICT" },
  { key: "date.timezone", label: "Timezone", hint: "e.g. Europe/Paris" },
];

/** Functions blocked by `disable_shell` (A1). */
export const SHELL_FUNCTIONS = ["exec", "system", "passthru", "shell_exec", "proc_open", "popen"];

/** Keys refused in extra directives (A1). */
export const FORBIDDEN_EXTRA_KEYS = new Set([
  "extension",
  "zend_extension",
  "open_basedir",
  "disable_functions",
  "disable_classes",
  "auto_prepend_file",
  "auto_append_file",
  "sendmail_path",
  "error_log",
  "upload_tmp_dir",
  "session.save_path",
  "user_ini.filename",
  "doc_root",
  "include_path",
]);

const KEY_RE = /^[a-z][a-z0-9_.]{0,63}$/;
const BAD_VALUE_CHARS = /[\n\r[\];"]/;

/** Max raw php.ini size accepted by the agent (A3). */
export const PHP_INI_MAX_BYTES = 512 * 1024;

/**
 * "256M" → 256, "1G" → 1024, "512K" → 0.5, "1048576" → 1. Returns null for
 * anything that is not a PHP shorthand size (e.g. "-1" or "").
 */
export function parseSizeMb(v: string | null | undefined): number | null {
  if (v == null) return null;
  const m = /^\s*(\d+(?:\.\d+)?)\s*([kmgKMG]?)\s*$/.exec(v);
  if (!m) return null;
  const n = parseFloat(m[1]);
  switch (m[2].toUpperCase()) {
    case "G": return n * 1024;
    case "M": return n;
    case "K": return n / 1024;
    default: return n / (1024 * 1024);
  }
}

/** 256 → "256M". */
export function formatSizeMb(mb: number): string {
  return `${Math.round(mb)}M`;
}

/**
 * The input text for a field, from a stored value. Size fields are edited as a
 * bare number of MB; everything else as-is.
 */
export function toInputText(field: PhpField, value: string | null | undefined): string {
  if (value == null) return "";
  if (field.kind === "size") {
    const mb = parseSizeMb(value);
    return mb == null ? value : String(Math.round(mb));
  }
  return value;
}

/** The stored value for an input text; "" means "no override" (null). */
export function fromInputText(field: PhpField, text: string): string | null {
  const t = text.trim();
  if (t === "") return null;
  if (field.kind === "size" && /^\d+$/.test(t)) return formatSizeMb(parseInt(t, 10));
  return t;
}

/** Client-side bound check, mirroring B1; null when fine. The server stays authoritative. */
export function validateFieldValue(field: PhpField, value: string | null): string | null {
  if (value == null) return null;
  if (field.kind === "size") {
    const mb = parseSizeMb(value);
    if (mb == null) return "Enter a size in MB";
    if (field.min != null && mb < field.min) return `Minimum ${field.min} MB`;
    if (field.max != null && mb > field.max) return `Maximum ${field.max} MB`;
    return null;
  }
  if (field.kind === "int") {
    if (!/^-?\d+$/.test(value)) return "Enter a whole number";
    const n = parseInt(value, 10);
    if (field.min != null && n < field.min) return `Minimum ${field.min}`;
    if (field.max != null && n > field.max) return `Maximum ${field.max}`;
    return null;
  }
  if (field.kind === "bool") {
    return value === "On" || value === "Off" ? null : "On or Off";
  }
  if (field.kind === "choice" && field.choices && field.choices.length > 0) {
    return field.choices.some((c) => c.value === value) ? null : "Pick a value from the list";
  }
  return null;
}

/**
 * The `values` part of a PUT: every edited key whose new value differs from the
 * site's current override. `edits` holds only what the user touched; null in it
 * means "reset to default". Returns an empty object when nothing changed.
 */
export function changedValues(
  current: Record<string, string>,
  edits: Record<string, string | null>,
): Record<string, string | null> {
  const out: Record<string, string | null> = {};
  for (const [k, v] of Object.entries(edits)) {
    const before = Object.prototype.hasOwnProperty.call(current, k) ? current[k] : null;
    if (v !== before) out[k] = v;
  }
  return out;
}

/** The pool keys that differ from `current` (B2 accepts a partial pool). */
export function changedPool(current: PhpPool, draft: PhpPool): Partial<PhpPool> {
  const out: Partial<PhpPool> = {};
  (Object.keys(draft) as (keyof PhpPool)[]).forEach((k) => {
    if (draft[k] !== current[k]) (out as Record<string, unknown>)[k] = draft[k];
  });
  return out;
}

/** Extra directive rows without the blank ones, trimmed. */
export function cleanExtra(rows: [string, string][]): [string, string][] {
  return rows
    .map(([k, v]) => [k.trim(), v.trim()] as [string, string])
    .filter(([k, v]) => k !== "" || v !== "");
}

export function extraEqual(a: [string, string][], b: [string, string][]): boolean {
  return a.length === b.length && a.every(([k, v], i) => b[i][0] === k && b[i][1] === v);
}

/** Validate one extra directive (A1 rules); null when fine. */
export function validateExtra(key: string, value: string): string | null {
  if (!KEY_RE.test(key)) return "Key: lowercase letters, digits, '_' and '.', starting with a letter";
  if (FORBIDDEN_EXTRA_KEYS.has(key)) return `${key} cannot be set here`;
  if (value.length > 256) return "Value: 256 characters maximum";
  if (BAD_VALUE_CHARS.test(value)) return 'Value cannot contain line breaks, [ ] ; or "';
  return null;
}

/** Validate a global php.ini value (A3 character rules); null when fine. */
export function validateIniValue(value: string): string | null {
  if (value.trim() === "") return "Enter a value";
  if (value.length > 256) return "256 characters maximum";
  if (BAD_VALUE_CHARS.test(value)) return 'Cannot contain line breaks, [ ] ; or "';
  return null;
}

/** The global php.ini `values` that changed (never null or empty). */
export function changedIniValues(
  current: Record<string, string | null>,
  draft: Record<string, string>,
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(draft)) {
    const t = v.trim();
    if (t === "") continue;
    if (t !== (current[k] ?? "")) out[k] = t;
  }
  return out;
}

/** Byte length of a string as UTF-8. */
export function utf8Bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}
