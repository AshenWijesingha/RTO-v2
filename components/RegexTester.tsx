'use client'

import React, { useState, useMemo } from 'react'
import { copyToClipboard } from '@/lib/utils'

interface RegexFlag {
  flag: string
  label: string
  description: string
}

interface MatchResult {
  index: number
  match: string
  start: number
  end: number
  groups: string[]
}

interface SecurityPattern {
  name: string
  category: string
  pattern: string
  description: string
}

interface CheatSheetEntry {
  syntax: string
  description: string
}

interface CheatSheetSection {
  title: string
  entries: CheatSheetEntry[]
}

const FLAGS: RegexFlag[] = [
  { flag: 'g', label: 'g', description: 'Global' },
  { flag: 'i', label: 'i', description: 'Case Insensitive' },
  { flag: 'm', label: 'm', description: 'Multiline' },
  { flag: 's', label: 's', description: 'DotAll' },
  { flag: 'u', label: 'u', description: 'Unicode' },
]

const SECURITY_PATTERNS: SecurityPattern[] = [
  // Network/IOC Detection
  { name: 'IPv4 Address', category: 'Network/IOC Detection', pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b', description: 'Matches valid IPv4 addresses (0.0.0.0 - 255.255.255.255)' },
  { name: 'IPv6 Address', category: 'Network/IOC Detection', pattern: '\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b', description: 'Matches full IPv6 addresses' },
  { name: 'MAC Address', category: 'Network/IOC Detection', pattern: '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b', description: 'Matches MAC addresses with colon or hyphen separators' },
  { name: 'URL', category: 'Network/IOC Detection', pattern: 'https?:\\/\\/(?:[-\\w.]|(?:%[\\da-fA-F]{2}))+[^\\s]*', description: 'Matches HTTP and HTTPS URLs' },
  { name: 'Email', category: 'Network/IOC Detection', pattern: '\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', description: 'Matches email addresses' },
  { name: 'Domain', category: 'Network/IOC Detection', pattern: '\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b', description: 'Matches domain names' },
  // Hash Patterns
  { name: 'MD5', category: 'Hash Patterns', pattern: '\\b[a-fA-F0-9]{32}\\b', description: 'Matches MD5 hash values (32 hex characters)' },
  { name: 'SHA-1', category: 'Hash Patterns', pattern: '\\b[a-fA-F0-9]{40}\\b', description: 'Matches SHA-1 hash values (40 hex characters)' },
  { name: 'SHA-256', category: 'Hash Patterns', pattern: '\\b[a-fA-F0-9]{64}\\b', description: 'Matches SHA-256 hash values (64 hex characters)' },
  // Log Analysis
  { name: 'Apache Common Log', category: 'Log Analysis', pattern: '^(\\S+) (\\S+) (\\S+) \\[([^\\]]+)\\] "(\\S+) (\\S+) (\\S+)" (\\d+) (\\d+)', description: 'Parses Apache common log format with capture groups for each field' },
  { name: 'Windows Event ID', category: 'Log Analysis', pattern: 'EventCode=(\\d+)|Event ID:\\s*(\\d+)', description: 'Extracts Windows Event IDs from log entries' },
  { name: 'Syslog', category: 'Log Analysis', pattern: '^<(\\d+)>(\\w{3}\\s+\\d{1,2}\\s+\\d{2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+(\\S+?)(?:\\[(\\d+)\\])?:\\s*(.*)', description: 'Parses syslog message format with priority, timestamp, host, and message' },
  // Attack Patterns
  { name: 'SQL Injection', category: 'Attack Patterns', pattern: "(?:')|(?:--)|(/\\*(?:.|[\\n\\r])*?\\*/)|(\\b(select|union|insert|update|delete|drop|alter|create|exec)\\b)", description: 'Detects common SQL injection patterns and keywords' },
  { name: 'XSS', category: 'Attack Patterns', pattern: '<script[^>]*>[\\s\\S]*?<\\/script>|javascript:|on\\w+\\s*=', description: 'Detects cross-site scripting attempts including script tags and event handlers' },
  { name: 'Path Traversal', category: 'Attack Patterns', pattern: '\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e\\/|\\.\\.%2f', description: 'Detects directory traversal attempts including URL-encoded variants' },
  { name: 'Command Injection', category: 'Attack Patterns', pattern: '[;&|]{1,2}|\\$\\(|\\`[^`]*\\`', description: 'Detects shell command injection via chaining operators and subshells' },
  { name: 'Base64 Encoded String', category: 'Attack Patterns', pattern: '(?:[A-Za-z0-9+\\/]{4})*(?:[A-Za-z0-9+\\/]{2}==|[A-Za-z0-9+\\/]{3}=)?', description: 'Matches Base64-encoded strings with proper padding' },
  { name: 'CVE ID', category: 'Attack Patterns', pattern: 'CVE-\\d{4}-\\d{4,}', description: 'Matches CVE identifiers (e.g., CVE-2024-12345)' },
  // Credential Patterns
  { name: 'AWS Access Key', category: 'Credential Patterns', pattern: 'AKIA[0-9A-Z]{16}', description: 'Matches AWS access key IDs starting with AKIA' },
  { name: 'AWS Secret Key', category: 'Credential Patterns', pattern: '(?<![A-Za-z0-9\\/+=])[A-Za-z0-9\\/+=]{40}(?![A-Za-z0-9\\/+=])', description: 'Matches 40-character AWS secret access keys' },
  { name: 'Generic API Key', category: 'Credential Patterns', pattern: '(?:api[_-]?key|apikey|api_secret)[\\s:=]+[\'"]?([A-Za-z0-9_-]{20,})[\'"]?', description: 'Matches common API key patterns in configuration files' },
  { name: 'Private Key', category: 'Credential Patterns', pattern: '-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----', description: 'Detects PEM-encoded private key headers' },
  { name: 'JWT Token', category: 'Credential Patterns', pattern: 'eyJ[A-Za-z0-9-_]+\\.eyJ[A-Za-z0-9-_]+\\.[A-Za-z0-9-_]+', description: 'Matches JSON Web Tokens (JWT) with header.payload.signature format' },
]

const CHEAT_SHEET: CheatSheetSection[] = [
  {
    title: 'Characters',
    entries: [
      { syntax: '.', description: 'Any character except newline' },
      { syntax: '\\d', description: 'Digit [0-9]' },
      { syntax: '\\D', description: 'Non-digit [^0-9]' },
      { syntax: '\\w', description: 'Word character [A-Za-z0-9_]' },
      { syntax: '\\W', description: 'Non-word character' },
      { syntax: '\\s', description: 'Whitespace (space, tab, newline)' },
      { syntax: '\\S', description: 'Non-whitespace' },
      { syntax: '\\b', description: 'Word boundary' },
      { syntax: '\\B', description: 'Non-word boundary' },
      { syntax: '^', description: 'Start of string/line' },
      { syntax: '$', description: 'End of string/line' },
    ],
  },
  {
    title: 'Quantifiers',
    entries: [
      { syntax: '*', description: 'Zero or more' },
      { syntax: '+', description: 'One or more' },
      { syntax: '?', description: 'Zero or one (optional)' },
      { syntax: '{n}', description: 'Exactly n times' },
      { syntax: '{n,}', description: 'n or more times' },
      { syntax: '{n,m}', description: 'Between n and m times' },
      { syntax: '*?', description: 'Zero or more (lazy)' },
      { syntax: '+?', description: 'One or more (lazy)' },
    ],
  },
  {
    title: 'Groups & Lookaround',
    entries: [
      { syntax: '(abc)', description: 'Capturing group' },
      { syntax: '(?:abc)', description: 'Non-capturing group' },
      { syntax: '(?=abc)', description: 'Positive lookahead' },
      { syntax: '(?!abc)', description: 'Negative lookahead' },
      { syntax: '(?<=abc)', description: 'Positive lookbehind' },
      { syntax: '(?<!abc)', description: 'Negative lookbehind' },
      { syntax: '(?<name>abc)', description: 'Named capturing group' },
      { syntax: '\\1', description: 'Backreference to group 1' },
    ],
  },
  {
    title: 'Character Classes',
    entries: [
      { syntax: '[abc]', description: 'Match a, b, or c' },
      { syntax: '[^abc]', description: 'Match anything except a, b, or c' },
      { syntax: '[a-z]', description: 'Match range a through z' },
      { syntax: '[A-Z]', description: 'Match range A through Z' },
      { syntax: '[0-9]', description: 'Match range 0 through 9' },
      { syntax: '[a-zA-Z0-9]', description: 'Match alphanumeric characters' },
    ],
  },
  {
    title: 'Escapes',
    entries: [
      { syntax: '\\n', description: 'Newline' },
      { syntax: '\\t', description: 'Tab' },
      { syntax: '\\r', description: 'Carriage return' },
      { syntax: '\\\\', description: 'Literal backslash' },
      { syntax: '\\.', description: 'Literal dot' },
      { syntax: '\\*', description: 'Literal asterisk' },
    ],
  },
  {
    title: 'Flags',
    entries: [
      { syntax: 'g', description: 'Global - find all matches' },
      { syntax: 'i', description: 'Case insensitive matching' },
      { syntax: 'm', description: 'Multiline - ^ and $ match line boundaries' },
      { syntax: 's', description: 'DotAll - . matches newline characters' },
      { syntax: 'u', description: 'Unicode - treat pattern as Unicode' },
      { syntax: 'y', description: 'Sticky - match from lastIndex only' },
    ],
  },
]

export default function RegexTester() {
  const [activeTab, setActiveTab] = useState<'tester' | 'library' | 'cheatsheet'>('tester')
  const [pattern, setPattern] = useState('')
  const [selectedFlags, setSelectedFlags] = useState<Record<string, boolean>>({ g: true, i: false, m: false, s: false, u: false })
  const [testString, setTestString] = useState('')
  const [replacement, setReplacement] = useState('')
  const [libraryFilter, setLibraryFilter] = useState('')
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const flagString = Object.entries(selectedFlags)
    .filter(([, v]) => v)
    .map(([k]) => k)
    .join('')

  const toggleFlag = (flag: string) => {
    setSelectedFlags(prev => ({ ...prev, [flag]: !prev[flag] }))
  }

  const { matches, error, highlightedText, replaceResult } = useMemo(() => {
    if (!pattern) return { matches: [] as MatchResult[], error: null, highlightedText: testString, replaceResult: '' }

    try {
      const regex = new RegExp(pattern, flagString)
      const results: MatchResult[] = []
      let match: RegExpExecArray | null

      if (flagString.includes('g')) {
        while ((match = regex.exec(testString)) !== null) {
          results.push({
            index: results.length,
            match: match[0],
            start: match.index,
            end: match.index + match[0].length,
            groups: match.slice(1).filter(g => g !== undefined),
          })
          if (match[0].length === 0) {
            regex.lastIndex++
          }
        }
      } else {
        match = regex.exec(testString)
        if (match) {
          results.push({
            index: 0,
            match: match[0],
            start: match.index,
            end: match.index + match[0].length,
            groups: match.slice(1).filter(g => g !== undefined),
          })
        }
      }

      // Build highlighted text
      let highlighted = testString
      if (results.length > 0) {
        const parts: Array<{ text: string; isMatch: boolean }> = []
        let lastEnd = 0
        const sorted = [...results].sort((a, b) => a.start - b.start)
        for (const r of sorted) {
          if (r.start > lastEnd) {
            parts.push({ text: testString.slice(lastEnd, r.start), isMatch: false })
          }
          parts.push({ text: testString.slice(r.start, r.end), isMatch: true })
          lastEnd = r.end
        }
        if (lastEnd < testString.length) {
          parts.push({ text: testString.slice(lastEnd), isMatch: false })
        }
        highlighted = parts.map((p, i) =>
          p.isMatch ? `<mark key=${i}>${escapeHtml(p.text)}</mark>` : escapeHtml(p.text)
        ).join('')
      } else {
        highlighted = escapeHtml(testString)
      }

      // Compute replace result
      let replResult = ''
      if (replacement !== undefined) {
        try {
          const replRegex = new RegExp(pattern, flagString)
          replResult = testString.replace(replRegex, replacement)
        } catch {
          replResult = ''
        }
      }

      return { matches: results, error: null, highlightedText: highlighted, replaceResult: replResult }
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : 'Invalid regex'
      return { matches: [] as MatchResult[], error: message, highlightedText: escapeHtml(testString), replaceResult: '' }
    }
  }, [pattern, flagString, testString, replacement])

  function escapeHtml(str: string): string {
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
  }

  const loadPattern = (p: SecurityPattern) => {
    setPattern(p.pattern)
    setActiveTab('tester')
  }

  const handleCopy = (text: string, id: string) => {
    copyToClipboard(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 1500)
  }

  const categories = [...new Set(SECURITY_PATTERNS.map(p => p.category))]

  const filteredPatterns = libraryFilter
    ? SECURITY_PATTERNS.filter(p =>
        p.name.toLowerCase().includes(libraryFilter.toLowerCase()) ||
        p.category.toLowerCase().includes(libraryFilter.toLowerCase()) ||
        p.description.toLowerCase().includes(libraryFilter.toLowerCase())
      )
    : SECURITY_PATTERNS

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="section-heading">Regex Tester</h1>
          <p className="section-subheading">
            Test regex patterns for SIEM detection rules and payload crafting
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="badge badge-success">Live Testing</span>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex gap-2 flex-wrap">
        <button
          className={`tab-btn ${activeTab === 'tester' ? 'active' : ''}`}
          onClick={() => setActiveTab('tester')}
        >
          🔍 Regex Tester
        </button>
        <button
          className={`tab-btn ${activeTab === 'library' ? 'active' : ''}`}
          onClick={() => setActiveTab('library')}
        >
          📚 Security Regex Library
        </button>
        <button
          className={`tab-btn ${activeTab === 'cheatsheet' ? 'active' : ''}`}
          onClick={() => setActiveTab('cheatsheet')}
        >
          📋 Cheat Sheet
        </button>
      </div>

      {/* Tab 1: Regex Tester */}
      {activeTab === 'tester' && (
        <div className="space-y-4">
          {/* Pattern Input */}
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header">
              <h2 className="card-title">Pattern</h2>
              {error && <span className="badge badge-critical">Error</span>}
              {!error && pattern && <span className="badge badge-success">{matches.length} match{matches.length !== 1 ? 'es' : ''}</span>}
            </div>
            <div className="space-y-3">
              <div className="flex gap-2 items-center flex-wrap">
                <span className="text-gray-400 text-sm font-mono">/</span>
                <input
                  type="text"
                  className="cyber-input flex-1"
                  placeholder="Enter regex pattern..."
                  value={pattern}
                  onChange={e => setPattern(e.target.value)}
                  spellCheck={false}
                />
                <span className="text-gray-400 text-sm font-mono">/{flagString}</span>
              </div>
              {error && (
                <div className="text-red-400 text-sm font-mono px-2 py-1 rounded" style={{ background: 'rgba(255,68,68,0.1)' }}>
                  ⚠ {error}
                </div>
              )}
              {/* Flags */}
              <div className="flex gap-3 flex-wrap items-center">
                <span className="text-gray-400 text-sm">Flags:</span>
                {FLAGS.map(f => (
                  <label key={f.flag} className="flex items-center gap-1.5 cursor-pointer select-none">
                    <input
                      type="checkbox"
                      checked={selectedFlags[f.flag] || false}
                      onChange={() => toggleFlag(f.flag)}
                      className="accent-cyan-400"
                    />
                    <code className="text-cyan-400 text-sm">{f.label}</code>
                    <span className="text-gray-500 text-xs">({f.description})</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Test String */}
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header">
              <h2 className="card-title">Test String</h2>
              {testString && (
                <button
                  className="btn-primary text-xs px-2 py-1"
                  onClick={() => handleCopy(testString, 'test-string')}
                >
                  {copiedId === 'test-string' ? '✓ Copied' : 'Copy'}
                </button>
              )}
            </div>
            <textarea
              className="cyber-textarea w-full"
              rows={6}
              placeholder="Enter test string..."
              value={testString}
              onChange={e => setTestString(e.target.value)}
              spellCheck={false}
            />
          </div>

          {/* Highlighted Results */}
          {testString && pattern && !error && (
            <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="card-header">
                <h2 className="card-title">Highlighted Matches</h2>
                <span className="badge badge-warning">{matches.length} found</span>
              </div>
              <div
                className="code-block whitespace-pre-wrap break-all"
                style={{ lineHeight: '1.8' }}
                dangerouslySetInnerHTML={{
                  __html: highlightedText.replace(
                    /<mark key=\d+>/g,
                    '<span style="background:rgba(0,212,255,0.25);color:#00d4ff;border-radius:2px;padding:1px 3px;border:1px solid rgba(0,212,255,0.4);">'
                  ).replace(/<\/mark>/g, '</span>')
                }}
              />
            </div>
          )}

          {/* Match Details */}
          {matches.length > 0 && (
            <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="card-header">
                <h2 className="card-title">Match Details</h2>
                <button
                  className="btn-primary text-xs px-2 py-1"
                  onClick={() => handleCopy(JSON.stringify(matches, null, 2), 'matches')}
                >
                  {copiedId === 'matches' ? '✓ Copied' : 'Copy JSON'}
                </button>
              </div>
              <div className="space-y-2 max-h-80 overflow-y-auto">
                {matches.map(m => (
                  <div
                    key={m.index}
                    className="rounded p-3 text-sm font-mono"
                    style={{ background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.08)' }}
                  >
                    <div className="flex items-center gap-3 flex-wrap">
                      <span className="badge badge-success">#{m.index}</span>
                      <span className="text-cyan-300">&quot;{m.match}&quot;</span>
                      <span className="text-gray-500">
                        pos {m.start}–{m.end}
                      </span>
                    </div>
                    {m.groups.length > 0 && (
                      <div className="mt-2 pl-4 border-l-2 border-cyan-800 space-y-1">
                        <span className="text-gray-400 text-xs">Capture Groups:</span>
                        {m.groups.map((g, gi) => (
                          <div key={gi} className="text-yellow-300 text-xs">
                            ${gi + 1}: &quot;{g}&quot;
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Replace Section */}
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <div className="card-header">
              <h2 className="card-title">Replace</h2>
            </div>
            <div className="space-y-3">
              <input
                type="text"
                className="cyber-input w-full"
                placeholder="Replacement pattern (supports $1, $2, etc.)..."
                value={replacement}
                onChange={e => setReplacement(e.target.value)}
                spellCheck={false}
              />
              {replacement && testString && pattern && !error && (
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-gray-400 text-xs">Result:</span>
                    <button
                      className="btn-primary text-xs px-2 py-1"
                      onClick={() => handleCopy(replaceResult, 'replace')}
                    >
                      {copiedId === 'replace' ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                  <div className="code-block whitespace-pre-wrap break-all">
                    {replaceResult}
                  </div>
                </div>
              )}
              <p className="text-gray-500 text-xs">
                Use $1, $2, etc. for capture group references. Use $&amp; for the entire match.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Security Regex Library */}
      {activeTab === 'library' && (
        <div className="space-y-4">
          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <input
              type="text"
              className="cyber-input w-full"
              placeholder="Search patterns by name, category, or description..."
              value={libraryFilter}
              onChange={e => setLibraryFilter(e.target.value)}
            />
          </div>

          {categories.map(cat => {
            const catPatterns = filteredPatterns.filter(p => p.category === cat)
            if (catPatterns.length === 0) return null

            const categoryBadge = cat === 'Attack Patterns' ? 'badge-critical'
              : cat === 'Credential Patterns' ? 'badge-warning'
              : cat === 'Hash Patterns' ? 'badge-success'
              : 'badge'

            return (
              <div key={cat} className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                <div className="card-header">
                  <h2 className="card-title">{cat}</h2>
                  <span className={`badge ${categoryBadge}`}>{catPatterns.length}</span>
                </div>
                <div className="space-y-3">
                  {catPatterns.map(p => (
                    <div
                      key={p.name}
                      className="rounded p-3"
                      style={{ background: 'rgba(0,212,255,0.03)', border: '1px solid rgba(0,212,255,0.06)' }}
                    >
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div>
                          <span className="text-cyan-300 font-semibold text-sm">{p.name}</span>
                          <p className="text-gray-400 text-xs mt-0.5">{p.description}</p>
                        </div>
                        <div className="flex gap-1.5 shrink-0">
                          <button
                            className="btn-primary text-xs px-2 py-1"
                            onClick={() => loadPattern(p)}
                          >
                            Load
                          </button>
                          <button
                            className="btn-danger text-xs px-2 py-1"
                            onClick={() => handleCopy(p.pattern, `lib-${p.name}`)}
                          >
                            {copiedId === `lib-${p.name}` ? '✓' : 'Copy'}
                          </button>
                        </div>
                      </div>
                      <div className="code-block text-xs break-all">
                        {p.pattern}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Tab 3: Cheat Sheet */}
      {activeTab === 'cheatsheet' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {CHEAT_SHEET.map(section => (
            <div key={section.title} className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="card-header">
                <h2 className="card-title">{section.title}</h2>
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700">
                    <th className="text-left py-2 px-2 text-cyan-400 font-mono text-xs">Syntax</th>
                    <th className="text-left py-2 px-2 text-gray-400 text-xs">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {section.entries.map(entry => (
                    <tr key={entry.syntax} className="border-b border-gray-800 hover:bg-cyan-900/10 transition-colors">
                      <td className="py-1.5 px-2">
                        <code className="text-cyan-300 text-xs px-1.5 py-0.5 rounded" style={{ background: 'rgba(0,212,255,0.08)' }}>
                          {entry.syntax}
                        </code>
                      </td>
                      <td className="py-1.5 px-2 text-gray-300 text-xs">
                        {entry.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
