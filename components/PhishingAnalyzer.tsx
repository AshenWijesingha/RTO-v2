'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

/* ───────── types ───────── */

interface ParsedHeaders {
  raw: Record<string, string[]>
  from: string
  replyTo: string
  returnPath: string
  subject: string
  date: string
  messageId: string
  xMailer: string
  contentType: string
  receivedHops: string[]
  spf: string
  dkim: string
  dmarc: string
  suspiciousFlags: string[]
}

interface URLAnalysis {
  original: string
  protocol: string
  subdomain: string
  domain: string
  tld: string
  fullDomain: string
  path: string
  defanged: string
  flags: string[]
}

interface ExtractedIOCs {
  ipv4: string[]
  ipv6: string[]
  urls: string[]
  domains: string[]
  emails: string[]
  md5: string[]
  sha1: string[]
  sha256: string[]
  filenames: string[]
}

interface CheckItem {
  category: string
  items: { label: string; checked: boolean }[]
}

/* ───────── constants ───────── */

const PHISHING_KEYWORDS = [
  'login', 'verify', 'secure', 'account', 'update', 'confirm',
  'banking', 'paypal', 'microsoft', 'apple', 'google',
]

const MAX_NORMAL_HOPS = 5
const MAX_SAFE_URL_LENGTH = 75

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
  'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 'rb.gy',
]

const INITIAL_CHECKLIST: CheckItem[] = [
  {
    category: 'Header Anomalies',
    items: [
      { label: 'SPF record fails or is missing', checked: false },
      { label: 'DKIM signature fails or is missing', checked: false },
      { label: 'DMARC policy fails or is missing', checked: false },
      { label: 'From and Reply-To addresses do not match', checked: false },
      { label: 'Return-Path differs from From address', checked: false },
      { label: 'Unusual number of Received hops', checked: false },
    ],
  },
  {
    category: 'Sender Analysis',
    items: [
      { label: 'Sender domain recently registered', checked: false },
      { label: 'Sender domain has low reputation', checked: false },
      { label: 'Display name spoofs known brand', checked: false },
      { label: 'Free email service used for business context', checked: false },
      { label: 'Cousin / typo-squat domain detected', checked: false },
    ],
  },
  {
    category: 'Content Analysis',
    items: [
      { label: 'Creates sense of urgency or pressure', checked: false },
      { label: 'Threatens negative consequences', checked: false },
      { label: 'Offers too-good-to-be-true rewards', checked: false },
      { label: 'Contains grammar or spelling errors', checked: false },
      { label: 'Generic greeting (Dear Customer)', checked: false },
      { label: 'Requests sensitive information', checked: false },
      { label: 'Mismatched branding or logos', checked: false },
    ],
  },
  {
    category: 'Link Analysis',
    items: [
      { label: 'Hover URL differs from displayed text', checked: false },
      { label: 'URL uses IP address instead of domain', checked: false },
      { label: 'Shortened URL obscures destination', checked: false },
      { label: 'URL contains misspelled brand name', checked: false },
      { label: 'HTTP used instead of HTTPS', checked: false },
      { label: 'Excessive subdomains in URL', checked: false },
    ],
  },
  {
    category: 'Attachment Analysis',
    items: [
      { label: 'Double file extension (.pdf.exe)', checked: false },
      { label: 'Macro-enabled Office document (.docm, .xlsm)', checked: false },
      { label: 'Executable or script file type', checked: false },
      { label: 'Password-protected archive', checked: false },
      { label: 'Unexpected attachment from sender', checked: false },
    ],
  },
]

/* ───────── helpers ───────── */

function parseHeaders(raw: string): Record<string, string[]> {
  const unfolded = raw.replace(/\r?\n([ \t]+)/g, ' ')
  const headers: Record<string, string[]> = {}
  for (const line of unfolded.split(/\r?\n/)) {
    const match = line.match(/^([\w-]+):\s*(.*)/)
    if (match) {
      const [, key, value] = match
      const lk = key.toLowerCase()
      if (!headers[lk]) headers[lk] = []
      headers[lk].push(value)
    }
  }
  return headers
}

function firstVal(h: Record<string, string[]>, key: string): string {
  return h[key]?.[0] ?? ''
}

function extractAuthResult(authHeader: string, mechanism: string): string {
  const re = new RegExp(`${mechanism}=(\\w+)`, 'i')
  const m = authHeader.match(re)
  return m ? m[1].toLowerCase() : 'none'
}

function extractDomain(addr: string): string {
  const m = addr.match(/@([\w.-]+)/)
  return m ? m[1].toLowerCase() : ''
}

function analyzeHeaders(raw: string): ParsedHeaders {
  const h = parseHeaders(raw)

  const from = firstVal(h, 'from')
  const replyTo = firstVal(h, 'reply-to')
  const returnPath = firstVal(h, 'return-path')
  const authResults = firstVal(h, 'authentication-results')

  const spf = extractAuthResult(authResults, 'spf')
  const dkim = extractAuthResult(authResults, 'dkim')
  const dmarc = extractAuthResult(authResults, 'dmarc')

  const receivedHops = (h['received'] ?? []).slice()

  const flags: string[] = []

  // From / Reply-To mismatch
  if (replyTo && extractDomain(from) !== extractDomain(replyTo)) {
    flags.push('From and Reply-To domains do not match')
  }
  // Return-Path mismatch
  if (returnPath && extractDomain(from) !== extractDomain(returnPath)) {
    flags.push('Return-Path domain differs from From domain')
  }
  // Auth failures
  if (spf === 'fail' || spf === 'softfail') flags.push('SPF check failed')
  if (spf === 'none') flags.push('No SPF record found')
  if (dkim === 'fail') flags.push('DKIM signature failed')
  if (dkim === 'none') flags.push('No DKIM signature found')
  if (dmarc === 'fail') flags.push('DMARC check failed')
  if (dmarc === 'none') flags.push('No DMARC policy found')

  // Suspicious X-Mailer
  const xMailer = firstVal(h, 'x-mailer')
  if (xMailer) {
    const suspiciousMailers = ['phpmailer', 'swiftmailer', 'mass mail', 'bulk']
    if (suspiciousMailers.some(s => xMailer.toLowerCase().includes(s))) {
      flags.push(`Suspicious X-Mailer: ${xMailer}`)
    }
  }

  // Too many hops
  if (receivedHops.length > MAX_NORMAL_HOPS) {
    flags.push(`Excessive routing: ${receivedHops.length} hops detected (>${MAX_NORMAL_HOPS})`)
  }

  // Domain age hint
  const fromDomain = extractDomain(from)
  if (fromDomain) {
    flags.push(`Check domain registration age for: ${fromDomain}`)
  }

  return {
    raw: h,
    from,
    replyTo,
    returnPath,
    subject: firstVal(h, 'subject'),
    date: firstVal(h, 'date'),
    messageId: firstVal(h, 'message-id'),
    xMailer,
    contentType: firstVal(h, 'content-type'),
    receivedHops,
    spf,
    dkim,
    dmarc,
    suspiciousFlags: flags,
  }
}

function analyzeURL(url: string): URLAnalysis {
  const flags: string[] = []

  let parsed: URL | null = null
  try {
    parsed = new URL(url)
  } catch {
    // try adding protocol
    try {
      parsed = new URL('http://' + url)
    } catch {
      return {
        original: url,
        protocol: 'unknown',
        subdomain: '',
        domain: url,
        tld: '',
        fullDomain: url,
        path: '',
        defanged: url.replace(/\./g, '[.]').replace(/https?:\/\//i, 'hxxp://'),
        flags: ['Unable to parse URL'],
      }
    }
  }

  const protocol = parsed.protocol.replace(':', '')
  const hostname = parsed.hostname
  const path = parsed.pathname + parsed.search + parsed.hash

  // Protocol check
  if (protocol === 'http') {
    flags.push('Uses HTTP (not HTTPS) — data sent in cleartext')
  }

  // Domain breakdown
  const parts = hostname.split('.')
  let subdomain = ''
  let domain = hostname
  let tld = ''
  if (parts.length >= 3) {
    tld = parts.slice(-1).join('.')
    domain = parts.slice(-2, -1).join('.')
    subdomain = parts.slice(0, -2).join('.')
  } else if (parts.length === 2) {
    tld = parts[1]
    domain = parts[0]
  }

  // IP address instead of domain
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
    flags.push('Uses IP address instead of domain name')
  }

  // Punycode / homoglyphs
  if (hostname.startsWith('xn--') || hostname.includes('xn--')) {
    flags.push('Punycode (internationalized) domain — possible homoglyph attack')
  }

  // Excessive subdomains
  if (parts.length > 4) {
    flags.push(`Excessive subdomains (${parts.length - 2} levels)`)
  }

  // Phishing keywords
  const lower = url.toLowerCase()
  const found = PHISHING_KEYWORDS.filter(kw => lower.includes(kw))
  if (found.length > 0) {
    flags.push(`Phishing keywords detected: ${found.join(', ')}`)
  }

  // URL shorteners
  if (URL_SHORTENERS.some(s => hostname.toLowerCase().includes(s))) {
    flags.push('URL shortener detected — destination is obscured')
  }

  // Double extensions
  if (/\.\w{2,4}\.\w{2,4}$/.test(path) && /\.(exe|scr|bat|cmd|com|pif|js|vbs|wsf|msi)$/i.test(path)) {
    flags.push('Double file extension detected — possible executable disguise')
  }

  // @ symbol
  if (url.includes('@')) {
    flags.push('Contains @ symbol — may redirect to unexpected host')
  }

  // Long URL
  if (url.length > MAX_SAFE_URL_LENGTH) {
    flags.push(`Unusually long URL (${url.length} characters)`)
  }

  const defanged = url
    .replace(/https?:\/\//i, m => m.replace('http', 'hxxp'))
    .replace(/\./g, '[.]')

  return {
    original: url,
    protocol,
    subdomain,
    domain,
    tld,
    fullDomain: hostname,
    path,
    defanged,
    flags,
  }
}

function extractIOCs(text: string): ExtractedIOCs {
  const ipv4 = [...new Set(text.match(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g) ?? [])]
  const ipv6 = [...new Set(
    text.match(/\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:|\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b/g) ?? []
  )]
  const urls = [...new Set(text.match(/https?:\/\/[^\s<>"']+/gi) ?? [])]
  const emails = [...new Set(text.match(/[\w.-]+@[\w.-]+\.\w+/g) ?? [])]

  // Domains from URLs and emails
  const domainSet = new Set<string>()
  urls.forEach(u => { try { domainSet.add(new URL(u).hostname) } catch { /* skip */ } })
  emails.forEach(e => { const d = extractDomain(e); if (d) domainSet.add(d) })
  const domains = [...domainSet]

  // Hashes — use word-boundary matching to avoid partial matches
  const md5 = [...new Set((text.match(/\b[a-fA-F0-9]{32}\b/g) ?? []).filter(h => h.length === 32))]
  const sha1 = [...new Set((text.match(/\b[a-fA-F0-9]{40}\b/g) ?? []).filter(h => h.length === 40))]
  const sha256 = [...new Set((text.match(/\b[a-fA-F0-9]{64}\b/g) ?? []).filter(h => h.length === 64))]

  // Filenames with extensions
  const filenames = [...new Set(
    text.match(/\b[\w-]+\.(?:exe|dll|bat|cmd|ps1|vbs|js|wsf|scr|pif|msi|docm|xlsm|pptm|doc|xls|ppt|pdf|zip|rar|7z|iso|img)\b/gi) ?? []
  )]

  return { ipv4, ipv6, urls, domains, emails, md5, sha1, sha256, filenames }
}

function defangValue(v: string): string {
  return v
    .replace(/https?:\/\//gi, m => m.replace('http', 'hxxp'))
    .replace(/\./g, '[.]')
}

/* ───────── component ───────── */

export default function PhishingAnalyzer() {
  const [activeTab, setActiveTab] = useState<'headers' | 'url' | 'ioc' | 'checklist'>('headers')
  const [copied, setCopied] = useState('')

  // Tab 1 — Header Analyzer
  const [headerInput, setHeaderInput] = useState('')
  const [headerResult, setHeaderResult] = useState<ParsedHeaders | null>(null)

  // Tab 2 — URL Analyzer
  const [urlInput, setUrlInput] = useState('')
  const [urlResult, setUrlResult] = useState<URLAnalysis | null>(null)

  // Tab 3 — IOC Extractor
  const [iocInput, setIocInput] = useState('')
  const [iocResult, setIocResult] = useState<ExtractedIOCs | null>(null)
  const [defanged, setDefanged] = useState(false)

  // Tab 4 — Checklist
  const [checklist, setChecklist] = useState<CheckItem[]>(
    INITIAL_CHECKLIST.map(c => ({ ...c, items: c.items.map(i => ({ ...i })) }))
  )

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  /* ── auth badge helper ── */
  const authBadge = (result: string) => {
    if (result === 'pass') return <span className="badge badge-success">pass</span>
    if (result === 'fail' || result === 'softfail') return <span className="badge badge-critical">fail</span>
    return <span className="badge badge-warning">none</span>
  }

  /* ── IOC formats for export ── */
  const formatIOCExport = (iocs: ExtractedIOCs): string => {
    const lines: string[] = []
    if (iocs.ipv4.length) lines.push('## IPv4 Addresses', ...iocs.ipv4, '')
    if (iocs.ipv6.length) lines.push('## IPv6 Addresses', ...iocs.ipv6, '')
    if (iocs.urls.length) lines.push('## URLs', ...iocs.urls, '')
    if (iocs.domains.length) lines.push('## Domains', ...iocs.domains, '')
    if (iocs.emails.length) lines.push('## Email Addresses', ...iocs.emails, '')
    if (iocs.md5.length) lines.push('## MD5 Hashes', ...iocs.md5, '')
    if (iocs.sha1.length) lines.push('## SHA1 Hashes', ...iocs.sha1, '')
    if (iocs.sha256.length) lines.push('## SHA256 Hashes', ...iocs.sha256, '')
    if (iocs.filenames.length) lines.push('## Filenames', ...iocs.filenames, '')
    return lines.join('\n')
  }

  const formatIOCManagerExport = (iocs: ExtractedIOCs): string => {
    const entries: string[] = []
    const add = (type: string, values: string[]) => values.forEach(v => entries.push(`${type},${v}`))
    add('IPv4', iocs.ipv4)
    add('IPv6', iocs.ipv6)
    add('URL', iocs.urls)
    add('Domain', iocs.domains)
    add('Email', iocs.emails)
    add('MD5', iocs.md5)
    add('SHA1', iocs.sha1)
    add('SHA256', iocs.sha256)
    add('Filename', iocs.filenames)
    return 'type,value\n' + entries.join('\n')
  }

  const displayVal = (v: string) => (defanged ? defangValue(v) : v)

  const toggleCheck = (catIdx: number, itemIdx: number) => {
    setChecklist(prev =>
      prev.map((c, ci) =>
        ci !== catIdx
          ? c
          : {
              ...c,
              items: c.items.map((it, ii) =>
                ii !== itemIdx ? it : { ...it, checked: !it.checked }
              ),
            }
      )
    )
  }

  /* ──────────────── RENDER ──────────────── */

  return (
    <div className="space-y-6">
      <h1 className="section-heading text-2xl">🎣 Phishing Email Analyzer</h1>
      <p className="section-subheading text-sm">
        Analyze suspicious emails — inspect headers, URLs, extract IOCs and run through an indicators checklist.
      </p>

      {/* ── Tabs ── */}
      <div className="flex gap-2 flex-wrap">
        {([
          ['headers', '📧 Header Analyzer'],
          ['url', '🔗 URL Analyzer'],
          ['ioc', '🧬 IOC Extractor'],
          ['checklist', '✅ Indicators Checklist'],
        ] as const).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            className={`tab-btn ${activeTab === key ? 'active' : ''}`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ═══════════ TAB 1: Email Header Analyzer ═══════════ */}
      {activeTab === 'headers' && (
        <div className="space-y-4">
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header"><h2 className="card-title">Paste Raw Email Headers</h2></div>
            <div className="p-4 space-y-3">
              <textarea
                className="cyber-textarea w-full"
                rows={10}
                placeholder="Paste raw email headers here…"
                value={headerInput}
                onChange={e => setHeaderInput(e.target.value)}
              />
              <button
                className="btn-primary"
                onClick={() => { if (headerInput.trim()) setHeaderResult(analyzeHeaders(headerInput)) }}
              >
                🔍 Analyze Headers
              </button>
            </div>
          </div>

          {headerResult && (
            <>
              {/* Sender Info */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">Sender Information</h2></div>
                <div className="p-4">
                  <table className="cyber-table">
                    <thead>
                      <tr><th>Field</th><th>Value</th></tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td className="font-semibold text-blue-400">From</td>
                        <td>{headerResult.from || <span className="text-gray-500">—</span>}</td>
                      </tr>
                      <tr>
                        <td className="font-semibold text-blue-400">Reply-To</td>
                        <td>
                          {headerResult.replyTo || <span className="text-gray-500">—</span>}
                          {headerResult.replyTo && extractDomain(headerResult.from) !== extractDomain(headerResult.replyTo) && (
                            <span className="badge badge-critical ml-2">MISMATCH</span>
                          )}
                        </td>
                      </tr>
                      <tr>
                        <td className="font-semibold text-blue-400">Return-Path</td>
                        <td>
                          {headerResult.returnPath || <span className="text-gray-500">—</span>}
                          {headerResult.returnPath && extractDomain(headerResult.from) !== extractDomain(headerResult.returnPath) && (
                            <span className="badge badge-critical ml-2">MISMATCH</span>
                          )}
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Routing */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header">
                  <h2 className="card-title">
                    Routing (Received Hops)
                    <span className="badge badge-warning ml-2">{headerResult.receivedHops.length} hops</span>
                  </h2>
                </div>
                <div className="p-4 space-y-2">
                  {headerResult.receivedHops.length === 0 && (
                    <p className="text-gray-500 text-sm">No Received headers found.</p>
                  )}
                  {headerResult.receivedHops.map((hop, i) => (
                    <div key={i} className="code-block text-xs">
                      <span className="text-blue-400 font-bold">Hop {i + 1}:</span> {hop}
                    </div>
                  ))}
                </div>
              </div>

              {/* Authentication */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">Authentication Results</h2></div>
                <div className="p-4">
                  <table className="cyber-table">
                    <thead>
                      <tr><th>Mechanism</th><th>Result</th></tr>
                    </thead>
                    <tbody>
                      <tr><td className="font-semibold text-blue-400">SPF</td><td>{authBadge(headerResult.spf)}</td></tr>
                      <tr><td className="font-semibold text-blue-400">DKIM</td><td>{authBadge(headerResult.dkim)}</td></tr>
                      <tr><td className="font-semibold text-blue-400">DMARC</td><td>{authBadge(headerResult.dmarc)}</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Key Headers */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">Key Headers</h2></div>
                <div className="p-4">
                  <table className="cyber-table">
                    <thead>
                      <tr><th>Header</th><th>Value</th></tr>
                    </thead>
                    <tbody>
                      {[
                        ['Subject', headerResult.subject],
                        ['Date', headerResult.date],
                        ['Message-ID', headerResult.messageId],
                        ['X-Mailer', headerResult.xMailer],
                        ['Content-Type', headerResult.contentType],
                      ].map(([label, val]) => (
                        <tr key={label}>
                          <td className="font-semibold text-blue-400">{label}</td>
                          <td>{val || <span className="text-gray-500">—</span>}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Suspicious Indicators */}
              {headerResult.suspiciousFlags.length > 0 && (
                <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  <div className="card-header"><h2 className="card-title">⚠️ Suspicious Indicators</h2></div>
                  <div className="p-4 space-y-2">
                    {headerResult.suspiciousFlags.map((flag, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span className="badge badge-critical">!</span>
                        <span className="text-sm text-red-300">{flag}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ═══════════ TAB 2: URL / Link Analyzer ═══════════ */}
      {activeTab === 'url' && (
        <div className="space-y-4">
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header"><h2 className="card-title">Paste Suspicious URL</h2></div>
            <div className="p-4 space-y-3">
              <input
                className="cyber-input w-full"
                placeholder="https://suspicious-site.example.com/login?redirect=…"
                value={urlInput}
                onChange={e => setUrlInput(e.target.value)}
              />
              <button
                className="btn-primary"
                onClick={() => { if (urlInput.trim()) setUrlResult(analyzeURL(urlInput.trim())) }}
              >
                🔍 Analyze URL
              </button>
            </div>
          </div>

          {urlResult && (
            <>
              {/* Domain Breakdown */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">URL Breakdown</h2></div>
                <div className="p-4">
                  <table className="cyber-table">
                    <thead>
                      <tr><th>Property</th><th>Value</th></tr>
                    </thead>
                    <tbody>
                      <tr>
                        <td className="font-semibold text-blue-400">Protocol</td>
                        <td>
                          {urlResult.protocol}
                          {urlResult.protocol === 'http' && <span className="badge badge-warning ml-2">insecure</span>}
                        </td>
                      </tr>
                      <tr><td className="font-semibold text-blue-400">Full Domain</td><td>{urlResult.fullDomain}</td></tr>
                      {urlResult.subdomain && (
                        <tr><td className="font-semibold text-blue-400">Subdomain</td><td>{urlResult.subdomain}</td></tr>
                      )}
                      <tr><td className="font-semibold text-blue-400">Domain</td><td>{urlResult.domain}</td></tr>
                      <tr><td className="font-semibold text-blue-400">TLD</td><td>{urlResult.tld}</td></tr>
                      {urlResult.path && urlResult.path !== '/' && (
                        <tr><td className="font-semibold text-blue-400">Path</td><td className="break-all">{urlResult.path}</td></tr>
                      )}
                      <tr>
                        <td className="font-semibold text-blue-400">Defanged</td>
                        <td className="break-all font-mono text-xs">
                          {urlResult.defanged}
                          <button onClick={() => copy(urlResult.defanged, 'defanged')} className="ml-2 text-blue-400 hover:underline text-xs">
                            {copied === 'defanged' ? '✓ Copied' : '⧉ Copy'}
                          </button>
                        </td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Suspicious Patterns */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">Suspicious Pattern Detection</h2></div>
                <div className="p-4 space-y-2">
                  {urlResult.flags.length === 0 ? (
                    <p className="text-green-400 text-sm">✅ No suspicious patterns detected.</p>
                  ) : (
                    urlResult.flags.map((flag, i) => (
                      <div key={i} className="flex items-start gap-2">
                        <span className="badge badge-critical">!</span>
                        <span className="text-sm text-red-300">{flag}</span>
                      </div>
                    ))
                  )}
                </div>
              </div>

              {/* External Lookups */}
              <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header"><h2 className="card-title">External Lookups</h2></div>
                <div className="p-4 flex flex-wrap gap-2">
                  {[
                    { label: '🦠 VirusTotal', href: `https://www.virustotal.com/gui/search/${encodeURIComponent(urlResult.original)}` },
                    { label: '🔍 URLScan.io', href: `https://urlscan.io/search/#${encodeURIComponent(urlResult.original)}` },
                    { label: '🐟 PhishTank', href: `https://phishtank.org/target_search.php?target=${encodeURIComponent(urlResult.fullDomain)}` },
                    { label: '🛡 Google Safe Browsing', href: `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(urlResult.original)}` },
                  ].map(link => (
                    <a
                      key={link.label}
                      href={link.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="btn-primary text-xs inline-block"
                    >
                      {link.label}
                    </a>
                  ))}
                </div>
              </div>
            </>
          )}
        </div>
      )}

      {/* ═══════════ TAB 3: IOC Extractor ═══════════ */}
      {activeTab === 'ioc' && (
        <div className="space-y-4">
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header"><h2 className="card-title">Paste Email Body / Raw Email</h2></div>
            <div className="p-4 space-y-3">
              <textarea
                className="cyber-textarea w-full"
                rows={10}
                placeholder="Paste the full email body or raw email content…"
                value={iocInput}
                onChange={e => setIocInput(e.target.value)}
              />
              <div className="flex gap-2 flex-wrap">
                <button
                  className="btn-primary"
                  onClick={() => { if (iocInput.trim()) setIocResult(extractIOCs(iocInput)) }}
                >
                  🧬 Extract IOCs
                </button>
                {iocResult && (
                  <>
                    <button
                      className="btn-primary"
                      onClick={() => copy(formatIOCExport(iocResult), 'all-iocs')}
                    >
                      {copied === 'all-iocs' ? '✓ Copied All' : '📋 Copy All IOCs'}
                    </button>
                    <button
                      className="btn-primary"
                      onClick={() => copy(formatIOCManagerExport(iocResult), 'export-ioc')}
                    >
                      {copied === 'export-ioc' ? '✓ Copied' : '📤 Export to IOC Manager'}
                    </button>
                    <button
                      className={`tab-btn ${defanged ? 'active' : ''}`}
                      onClick={() => setDefanged(!defanged)}
                    >
                      {defanged ? '🔒 Defanged' : '🔓 Refanged'}
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>

          {iocResult && (
            <>
              {([
                ['IPv4 Addresses', iocResult.ipv4, 'ipv4'],
                ['IPv6 Addresses', iocResult.ipv6, 'ipv6'],
                ['URLs', iocResult.urls, 'urls'],
                ['Domains', iocResult.domains, 'domains'],
                ['Email Addresses', iocResult.emails, 'emails'],
                ['MD5 Hashes', iocResult.md5, 'md5'],
                ['SHA1 Hashes', iocResult.sha1, 'sha1'],
                ['SHA256 Hashes', iocResult.sha256, 'sha256'],
                ['Filenames', iocResult.filenames, 'filenames'],
              ] as [string, string[], string][]).map(([title, items, key]) =>
                items.length > 0 ? (
                  <div key={key} className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                    <div className="card-header">
                      <h2 className="card-title">{title} <span className="badge badge-warning">{items.length}</span></h2>
                    </div>
                    <div className="p-4">
                      <table className="cyber-table">
                        <thead>
                          <tr><th>#</th><th>Value</th><th>Copy</th></tr>
                        </thead>
                        <tbody>
                          {items.map((item, i) => (
                            <tr key={i}>
                              <td className="text-gray-500 text-xs">{i + 1}</td>
                              <td className="font-mono text-xs break-all">{displayVal(item)}</td>
                              <td>
                                <button
                                  onClick={() => copy(item, `${key}-${i}`)}
                                  className="text-xs text-blue-400 hover:underline"
                                >
                                  {copied === `${key}-${i}` ? '✓' : '⧉'}
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                ) : null
              )}

              {/* Empty state */}
              {Object.values(iocResult).every(v => (v as string[]).length === 0) && (
                <div className="card p-6 text-center text-gray-500" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  No IOCs found in the provided text.
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ═══════════ TAB 4: Phishing Indicators Checklist ═══════════ */}
      {activeTab === 'checklist' && (
        <div className="space-y-4">
          <p className="text-sm text-gray-400">
            Use this checklist when triaging a suspicious email. Check off each indicator you observe.
          </p>
          {checklist.map((cat, ci) => (
            <div key={ci} className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="card-header">
                <h2 className="card-title">
                  {cat.category}
                  <span className="badge badge-warning ml-2">
                    {cat.items.filter(i => i.checked).length}/{cat.items.length}
                  </span>
                </h2>
              </div>
              <div className="p-4 space-y-2">
                {cat.items.map((item, ii) => (
                  <label
                    key={ii}
                    className="flex items-center gap-3 cursor-pointer hover:bg-white/5 p-2 rounded transition-colors"
                  >
                    <input
                      type="checkbox"
                      checked={item.checked}
                      onChange={() => toggleCheck(ci, ii)}
                      className="accent-cyan-400 w-4 h-4"
                    />
                    <span className={`text-sm ${item.checked ? 'text-red-400 line-through' : 'text-gray-300'}`}>
                      {item.label}
                    </span>
                    {item.checked && <span className="badge badge-critical text-xs">Flagged</span>}
                  </label>
                ))}
              </div>
            </div>
          ))}

          {/* Summary */}
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header"><h2 className="card-title">Summary</h2></div>
            <div className="p-4">
              {(() => {
                const total = checklist.reduce((s, c) => s + c.items.length, 0)
                const flagged = checklist.reduce((s, c) => s + c.items.filter(i => i.checked).length, 0)
                const pct = total > 0 ? Math.round((flagged / total) * 100) : 0
                let verdict: { label: string; badge: string }
                if (pct === 0) verdict = { label: 'No indicators flagged', badge: 'badge-success' }
                else if (pct < 25) verdict = { label: 'Low suspicion', badge: 'badge-warning' }
                else if (pct < 50) verdict = { label: 'Moderate suspicion', badge: 'badge-warning' }
                else verdict = { label: 'High suspicion — likely phishing', badge: 'badge-critical' }

                return (
                  <div className="flex items-center gap-4">
                    <span className="text-lg font-bold text-blue-400">{flagged}/{total}</span>
                    <span className="text-sm text-gray-400">indicators flagged ({pct}%)</span>
                    <span className={`badge ${verdict.badge}`}>{verdict.label}</span>
                  </div>
                )
              })()}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
