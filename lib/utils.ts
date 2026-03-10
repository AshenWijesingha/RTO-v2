// ============================================================
// Blue Team Cyber Dashboard – Utility Library
// ============================================================

// ── Clipboard ──────────────────────────────────────────────
export async function copyToClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    const el = document.createElement('textarea')
    el.value = text
    el.style.position = 'fixed'
    el.style.opacity = '0'
    document.body.appendChild(el)
    el.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(el)
    return ok
  }
}

// ── Encoding helpers ───────────────────────────────────────
export function base64Encode(str: string): string {
  try {
    const bytes = new TextEncoder().encode(str)
    const binStr = Array.from(bytes, b => String.fromCharCode(b)).join('')
    return btoa(binStr)
  } catch {
    try { return btoa(str) } catch { return 'Encoding error' }
  }
}

export function base64Decode(str: string): string {
  try {
    const binStr = atob(str)
    const bytes = Uint8Array.from(binStr, c => c.charCodeAt(0))
    return new TextDecoder().decode(bytes)
  } catch {
    return 'Invalid Base64 input'
  }
}

export function hexEncode(str: string): string {
  return Array.from(str)
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
    .join('')
}

export function hexDecode(hex: string): string {
  const clean = hex.replace(/\s/g, '')
  if (clean.length % 2 !== 0) return 'Invalid hex string'
  try {
    return clean.match(/.{2}/g)!.map(b => String.fromCharCode(parseInt(b, 16))).join('')
  } catch {
    return 'Invalid hex input'
  }
}

export function urlEncode(str: string): string { return encodeURIComponent(str) }
export function urlDecode(str: string): string {
  try { return decodeURIComponent(str) } catch { return 'Invalid URL-encoded input' }
}

export function rot13(str: string): string {
  return str.replace(/[a-zA-Z]/g, c => {
    const base = c <= 'Z' ? 65 : 97
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
  })
}

export function htmlEncode(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

export function htmlDecode(str: string): string {
  return str
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&#x2F;/g, '/')
    .replace(/&#47;/g, '/')
}

export function binaryEncode(str: string): string {
  return Array.from(str)
    .map(c => c.charCodeAt(0).toString(2).padStart(8, '0'))
    .join(' ')
}

export function binaryDecode(bin: string): string {
  const groups = bin.trim().split(/\s+/)
  try {
    return groups.map(b => String.fromCharCode(parseInt(b, 2))).join('')
  } catch {
    return 'Invalid binary input'
  }
}

// ── Hash detection ─────────────────────────────────────────
export function identifyHash(hash: string): string {
  const h = hash.trim()
  const patterns: [RegExp, string][] = [
    [/^[a-f0-9]{32}$/i, 'MD5 (32 hex)'],
    [/^[a-f0-9]{40}$/i, 'SHA-1 (40 hex)'],
    [/^[a-f0-9]{56}$/i, 'SHA-224 (56 hex)'],
    [/^[a-f0-9]{64}$/i, 'SHA-256 (64 hex)'],
    [/^[a-f0-9]{96}$/i, 'SHA-384 (96 hex)'],
    [/^[a-f0-9]{128}$/i, 'SHA-512 (128 hex)'],
    [/^\$2[ayb]\$.{56}$/, 'bcrypt'],
    [/^\$1\$.{8,20}\$.{22}$/, 'MD5-crypt'],
    [/^\$5\$/, 'SHA-256-crypt'],
    [/^\$6\$/, 'SHA-512-crypt'],
    [/^[a-f0-9]{16}$/i, 'MySQL < 4.1 (16 hex)'],
    [/^\*[A-F0-9]{40}$/, 'MySQL >= 4.1'],
    [/^[a-z0-9]{13}$/, 'DES-crypt'],
    [/^[a-f0-9]{32}:[a-f0-9]{32}$/i, 'MD5 with salt'],
    [/^sha256:[0-9]+:.{44}$/, 'Django SHA-256'],
  ]
  for (const [rx, name] of patterns) if (rx.test(h)) return name
  return 'Unknown hash type'
}

// ── CVSS Scoring ───────────────────────────────────────────
export interface CVSSv3 {
  AV: string; AC: string; PR: string; UI: string;
  S: string;  C: string;  I: string;  A: string;
}

export function calcCVSS3(v: CVSSv3): { score: number; rating: string } {
  const avMap: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 }
  const acMap: Record<string, number> = { L: 0.77, H: 0.44 }
  const prMap: Record<string, number> = {
    N_U: 0.85, L_U: 0.62, H_U: 0.27,
    N_C: 0.85, L_C: 0.68, H_C: 0.50,
  }
  const uiMap: Record<string, number> = { N: 0.85, R: 0.62 }
  const impMap: Record<string, number> = { N: 0, L: 0.22, H: 0.56 }

  const av = avMap[v.AV] ?? 0
  const ac = acMap[v.AC] ?? 0
  const prKey = v.PR + '_' + (v.S === 'C' ? 'C' : 'U')
  const pr = prMap[prKey] ?? 0.85
  const ui = uiMap[v.UI] ?? 0
  const ci = impMap[v.C] ?? 0
  const ii = impMap[v.I] ?? 0
  const ai = impMap[v.A] ?? 0

  const iss = 1 - (1 - ci) * (1 - ii) * (1 - ai)
  let isc: number
  if (v.S === 'U') isc = 6.42 * iss
  else isc = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)

  if (isc <= 0) return { score: 0, rating: 'None' }

  const esc = 8.22 * av * ac * pr * ui
  let score: number
  if (v.S === 'U') score = Math.min(isc + esc, 10)
  else score = Math.min(1.08 * (isc + esc), 10)

  score = Math.round(score * 10) / 10

  let rating = 'None'
  if (score >= 9.0) rating = 'Critical'
  else if (score >= 7.0) rating = 'High'
  else if (score >= 4.0) rating = 'Medium'
  else if (score > 0) rating = 'Low'

  return { score, rating }
}

// ── IOC type detection ─────────────────────────────────────
export type IOCType = 'IPv4' | 'IPv6' | 'Domain' | 'URL' | 'MD5' | 'SHA1' | 'SHA256' | 'Email' | 'CVE' | 'Unknown'

export function detectIOCType(value: string): IOCType {
  const v = value.trim()
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'IPv4'
  if (/^[a-f0-9:]{2,39}$/i.test(v) && v.includes(':')) return 'IPv6'
  if (/^https?:\/\//i.test(v)) return 'URL'
  if (/^[a-f0-9]{64}$/i.test(v)) return 'SHA256'
  if (/^[a-f0-9]{40}$/i.test(v)) return 'SHA1'
  if (/^[a-f0-9]{32}$/i.test(v)) return 'MD5'
  if (/^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/.test(v)) return 'Email'
  if (/^CVE-\d{4}-\d+$/i.test(v)) return 'CVE'
  if (/^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$/.test(v)) return 'Domain'
  return 'Unknown'
}

// ── Defang / Refang ────────────────────────────────────────
export function defang(ioc: string): string {
  return ioc
    .replace(/\./g, '[.]')
    .replace(/https?:\/\//gi, match => match.replace('://', '[://]'))
    .replace(/@/g, '[@]')
}

export function refang(ioc: string): string {
  return ioc
    .replace(/\[\.\]/g, '.')
    .replace(/\[:\/\/\]/g, '://')
    .replace(/\[@\]/g, '@')
}

// ── Date helpers ───────────────────────────────────────────
export function now(): string { return new Date().toISOString() }
export function formatDate(iso: string): string {
  return new Date(iso).toLocaleString()
}

// ── Export helpers ─────────────────────────────────────────
export function downloadText(content: string, filename: string, mime = 'text/plain') {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function downloadJSON(data: unknown, filename: string) {
  downloadText(JSON.stringify(data, null, 2), filename, 'application/json')
}

export function toCSV(rows: Record<string, unknown>[]): string {
  if (!rows.length) return ''
  const keys = Object.keys(rows[0])
  const header = keys.join(',')
  const body = rows.map(r =>
    keys.map(k => {
      const v = String(r[k] ?? '')
      return v.includes(',') || v.includes('"') || v.includes('\n')
        ? `"${v.replace(/"/g, '""')}"`
        : v
    }).join(',')
  ).join('\n')
  return header + '\n' + body
}

// ── CVSS colour helper ─────────────────────────────────────
export function cvssColor(rating: string): string {
  const m: Record<string, string> = {
    Critical: '#ff4444', High: '#ff6b35',
    Medium: '#ffd700', Low: '#00d4ff', None: '#6b7280',
  }
  return m[rating] ?? '#6b7280'
}

// ── localStorage wrapper ───────────────────────────────────
export function lsGet<T>(key: string, fallback: T): T {
  if (typeof window === 'undefined') return fallback
  try {
    const raw = localStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch { return fallback }
}

export function lsSet(key: string, value: unknown) {
  if (typeof window === 'undefined') return
  try { localStorage.setItem(key, JSON.stringify(value)) } catch (e) { console.error('localStorage write error:', e) }
}

// ── API request wrapper ────────────────────────────────────
export async function fetchWithTimeout(
  url: string,
  options: RequestInit = {},
  timeoutMs = 10000
): Promise<Response> {
  const controller = new AbortController()
  const id = setTimeout(() => controller.abort(), timeoutMs)
  try {
    const res = await fetch(url, { ...options, signal: controller.signal })
    return res
  } finally {
    clearTimeout(id)
  }
}
