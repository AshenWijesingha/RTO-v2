'use client'

import React, { useState, useMemo, useCallback } from 'react'
import { copyToClipboard, lsGet, lsSet, downloadJSON } from '@/lib/utils'

// ── Types ──────────────────────────────────────────────────
interface NmapConfig {
  target: string
  scanType: string
  portOption: 'default' | 'specific' | 'range' | 'top' | 'all' | 'fast'
  specificPorts: string
  topPorts: string
  serviceDetection: boolean
  versionIntensity: string
  osDetection: boolean
  osGuess: boolean
  defaultScripts: boolean
  scriptCategories: string[]
  customScript: string
  timing: string
  hostDiscovery: string
  skipHostDiscovery: boolean
  aggressive: boolean
  fragment: boolean
  decoyIps: string
  spoofMac: string
  dataLength: string
  sourcePort: string
  minRate: string
  maxRetries: string
  hostTimeout: string
  scanDelay: string
  outputFormat: string
  outputFile: string
  verbosity: string
  extraFlags: string
}

interface ScanProfile {
  id: string
  name: string
  description: string
  config: Partial<NmapConfig>
  builtin?: boolean
}

interface HistoryEntry {
  id: string
  command: string
  timestamp: string
  label: string
}

// ── Constants ──────────────────────────────────────────────
const DEFAULT_CONFIG: NmapConfig = {
  target: '',
  scanType: '-sS',
  portOption: 'default',
  specificPorts: '',
  topPorts: '100',
  serviceDetection: false,
  versionIntensity: '',
  osDetection: false,
  osGuess: false,
  defaultScripts: false,
  scriptCategories: [],
  customScript: '',
  timing: '',
  hostDiscovery: '',
  skipHostDiscovery: false,
  aggressive: false,
  fragment: false,
  decoyIps: '',
  spoofMac: '',
  dataLength: '',
  sourcePort: '',
  minRate: '',
  maxRetries: '',
  hostTimeout: '',
  scanDelay: '',
  outputFormat: '',
  outputFile: '',
  verbosity: '',
  extraFlags: '',
}

const SCAN_TYPES = [
  { value: '-sS', label: 'SYN Scan (Stealth)', desc: 'Half-open scan, fast & stealthy. Requires root.' },
  { value: '-sT', label: 'TCP Connect', desc: 'Full TCP handshake. No root required.' },
  { value: '-sU', label: 'UDP Scan', desc: 'Scan UDP ports. Slower but finds UDP services.' },
  { value: '-sA', label: 'ACK Scan', desc: 'Map firewall rulesets. Determines filtered vs unfiltered.' },
  { value: '-sF', label: 'FIN Scan', desc: 'Stealthier than SYN. Sets FIN flag only.' },
  { value: '-sX', label: 'Xmas Scan', desc: 'Sets FIN, PSH, URG flags. Stealthy but OS-dependent.' },
  { value: '-sN', label: 'NULL Scan', desc: 'No flags set. Can bypass some firewalls.' },
  { value: '-sW', label: 'Window Scan', desc: 'Like ACK but examines TCP window field.' },
  { value: '-sM', label: 'Maimon Scan', desc: 'FIN/ACK probe. Works on some BSD systems.' },
  { value: '-sn', label: 'Ping Scan (No Port)', desc: 'Host discovery only, no port scanning.' },
  { value: '-sI', label: 'Idle/Zombie Scan', desc: 'Extremely stealthy using idle host as proxy.' },
]

const TIMING_TEMPLATES = [
  { value: '', label: 'Default (T3)', desc: 'Normal timing' },
  { value: '-T0', label: 'T0 – Paranoid', desc: 'IDS evasion, 5 min between probes' },
  { value: '-T1', label: 'T1 – Sneaky', desc: 'IDS evasion, 15 sec between probes' },
  { value: '-T2', label: 'T2 – Polite', desc: 'Slower to reduce bandwidth/load' },
  { value: '-T3', label: 'T3 – Normal', desc: 'Default timing' },
  { value: '-T4', label: 'T4 – Aggressive', desc: 'Faster, assumes reliable network' },
  { value: '-T5', label: 'T5 – Insane', desc: 'Fastest, may miss results' },
]

const NSE_CATEGORIES = [
  { value: 'auth', desc: 'Authentication & credentials' },
  { value: 'broadcast', desc: 'Host discovery via broadcast' },
  { value: 'brute', desc: 'Brute-force password attacks' },
  { value: 'default', desc: 'Default safe scripts (-sC)' },
  { value: 'discovery', desc: 'Service and host discovery' },
  { value: 'dos', desc: 'Denial of service tests' },
  { value: 'exploit', desc: 'Active exploitation attempts' },
  { value: 'external', desc: 'Queries external services' },
  { value: 'fuzzer', desc: 'Fuzz testing inputs' },
  { value: 'intrusive', desc: 'May crash targets' },
  { value: 'malware', desc: 'Malware detection' },
  { value: 'safe', desc: 'Safe non-intrusive scripts' },
  { value: 'version', desc: 'Version detection scripts' },
  { value: 'vuln', desc: 'Vulnerability detection' },
]

const HOST_DISCOVERY_OPTIONS = [
  { value: '', label: 'Default', desc: 'ICMP echo + TCP SYN 443 + TCP ACK 80' },
  { value: '-PS', label: '-PS TCP SYN Ping', desc: 'Send SYN to discover hosts (default port 80)' },
  { value: '-PA', label: '-PA TCP ACK Ping', desc: 'Send ACK to discover hosts' },
  { value: '-PU', label: '-PU UDP Ping', desc: 'Send UDP to discover hosts' },
  { value: '-PE', label: '-PE ICMP Echo', desc: 'ICMP echo request (classic ping)' },
  { value: '-PP', label: '-PP ICMP Timestamp', desc: 'ICMP timestamp request' },
  { value: '-PM', label: '-PM ICMP Netmask', desc: 'ICMP address mask request' },
  { value: '-PR', label: '-PR ARP Ping', desc: 'ARP discovery (LAN only)' },
]

const OUTPUT_FORMATS = [
  { value: '', label: 'None (stdout)', desc: 'Output to terminal only' },
  { value: '-oN', label: '-oN Normal', desc: 'Normal human-readable output' },
  { value: '-oX', label: '-oX XML', desc: 'XML output for parsing' },
  { value: '-oG', label: '-oG Grepable', desc: 'Grepable format for scripting' },
  { value: '-oA', label: '-oA All Formats', desc: 'All three formats at once' },
  { value: '-oS', label: '-oS Script Kiddie', desc: 'Script kiddie output (l33t)' },
]

const BUILTIN_PROFILES: ScanProfile[] = [
  {
    id: 'quick',
    name: 'Quick Scan',
    description: 'Fast scan of top 100 TCP ports',
    builtin: true,
    config: { scanType: '-sS', portOption: 'top', topPorts: '100', timing: '-T4' },
  },
  {
    id: 'comprehensive',
    name: 'Comprehensive Scan',
    description: 'Full port scan with service detection, OS detection, and scripts',
    builtin: true,
    config: {
      scanType: '-sS', portOption: 'all', serviceDetection: true, versionIntensity: '5',
      osDetection: true, defaultScripts: true, timing: '-T4',
    },
  },
  {
    id: 'stealth',
    name: 'Stealth Scan',
    description: 'Low-profile scan to avoid detection',
    builtin: true,
    config: {
      scanType: '-sS', portOption: 'top', topPorts: '100', timing: '-T2',
      fragment: true, dataLength: '24',
    },
  },
  {
    id: 'vuln-scan',
    name: 'Vulnerability Scan',
    description: 'Scan common ports with vulnerability detection scripts',
    builtin: true,
    config: {
      scanType: '-sS', portOption: 'top', topPorts: '1000',
      serviceDetection: true, versionIntensity: '5',
      defaultScripts: true, scriptCategories: ['vuln'],
      timing: '-T4',
    },
  },
  {
    id: 'service-discovery',
    name: 'Service Discovery',
    description: 'Identify all running services and their versions',
    builtin: true,
    config: {
      scanType: '-sS', portOption: 'top', topPorts: '1000',
      serviceDetection: true, versionIntensity: '9',
      timing: '-T4',
    },
  },
  {
    id: 'ping-sweep',
    name: 'Ping Sweep',
    description: 'Discover live hosts on a network (no port scan)',
    builtin: true,
    config: { scanType: '-sn', portOption: 'default' },
  },
  {
    id: 'aggressive',
    name: 'Aggressive Scan',
    description: 'Combines OS detection, version detection, scripts, and traceroute (-A)',
    builtin: true,
    config: {
      scanType: '-sS', aggressive: true, portOption: 'top', topPorts: '1000', timing: '-T4',
    },
  },
  {
    id: 'firewall-detect',
    name: 'Firewall Detection',
    description: 'Detect firewall rules using ACK scan',
    builtin: true,
    config: {
      scanType: '-sA', portOption: 'top', topPorts: '100', timing: '-T4',
    },
  },
  {
    id: 'udp-scan',
    name: 'UDP Service Scan',
    description: 'Scan top UDP ports for services like DNS, SNMP, DHCP',
    builtin: true,
    config: {
      scanType: '-sU', portOption: 'top', topPorts: '100',
      serviceDetection: true, timing: '-T4',
    },
  },
]

// ── Helper: Build command ──────────────────────────────────
function buildCommand(c: NmapConfig): string {
  const parts: string[] = ['nmap']

  // Scan type
  if (c.scanType) parts.push(c.scanType)

  // Host discovery
  if (c.skipHostDiscovery) parts.push('-Pn')
  else if (c.hostDiscovery) parts.push(c.hostDiscovery)

  // Ports
  switch (c.portOption) {
    case 'specific':
      if (c.specificPorts.trim()) parts.push('-p', c.specificPorts.trim())
      break
    case 'range':
      if (c.specificPorts.trim()) parts.push('-p', c.specificPorts.trim())
      break
    case 'top':
      parts.push('--top-ports', c.topPorts || '100')
      break
    case 'all':
      parts.push('-p-')
      break
    case 'fast':
      parts.push('-F')
      break
  }

  // Service/version detection
  if (c.serviceDetection) {
    parts.push('-sV')
    if (c.versionIntensity) parts.push('--version-intensity', c.versionIntensity)
  }

  // OS detection
  if (c.osDetection) {
    parts.push('-O')
    if (c.osGuess) parts.push('--osscan-guess')
  }

  // Aggressive
  if (c.aggressive) parts.push('-A')

  // Scripts
  if (c.defaultScripts && c.scriptCategories.length === 0 && !c.customScript) {
    parts.push('-sC')
  } else {
    const scripts: string[] = []
    if (c.defaultScripts) scripts.push('default')
    scripts.push(...c.scriptCategories.filter(s => s !== 'default'))
    if (c.customScript.trim()) scripts.push(c.customScript.trim())
    if (scripts.length > 0) parts.push('--script', scripts.join(','))
  }

  // Timing
  if (c.timing) parts.push(c.timing)

  // Performance
  if (c.minRate) parts.push('--min-rate', c.minRate)
  if (c.maxRetries) parts.push('--max-retries', c.maxRetries)
  if (c.hostTimeout) parts.push('--host-timeout', c.hostTimeout)
  if (c.scanDelay) parts.push('--scan-delay', c.scanDelay)

  // Evasion
  if (c.fragment) parts.push('-f')
  if (c.decoyIps.trim()) parts.push('-D', c.decoyIps.trim())
  if (c.spoofMac.trim()) parts.push('--spoof-mac', c.spoofMac.trim())
  if (c.dataLength) parts.push('--data-length', c.dataLength)
  if (c.sourcePort) parts.push('--source-port', c.sourcePort)

  // Verbosity
  if (c.verbosity) parts.push(c.verbosity)

  // Output
  if (c.outputFormat && c.outputFile.trim()) {
    parts.push(c.outputFormat, c.outputFile.trim())
  }

  // Extra flags
  if (c.extraFlags.trim()) parts.push(c.extraFlags.trim())

  // Target (always last)
  if (c.target.trim()) parts.push(c.target.trim())

  return parts.join(' ')
}

// ── Helper: Build explanation ──────────────────────────────
function buildExplanation(c: NmapConfig): { flag: string; desc: string }[] {
  const items: { flag: string; desc: string }[] = [{ flag: 'nmap', desc: 'Network Mapper – network discovery and security auditing tool' }]

  const scanInfo = SCAN_TYPES.find(s => s.value === c.scanType)
  if (c.scanType && scanInfo) items.push({ flag: c.scanType, desc: scanInfo.desc })

  if (c.skipHostDiscovery) items.push({ flag: '-Pn', desc: 'Skip host discovery (treat all hosts as online)' })
  else if (c.hostDiscovery) {
    const hd = HOST_DISCOVERY_OPTIONS.find(h => h.value === c.hostDiscovery)
    if (hd) items.push({ flag: c.hostDiscovery, desc: hd.desc })
  }

  switch (c.portOption) {
    case 'specific':
    case 'range':
      if (c.specificPorts.trim()) items.push({ flag: `-p ${c.specificPorts.trim()}`, desc: `Scan specific port(s): ${c.specificPorts.trim()}` })
      break
    case 'top':
      items.push({ flag: `--top-ports ${c.topPorts || '100'}`, desc: `Scan top ${c.topPorts || '100'} most common ports` })
      break
    case 'all':
      items.push({ flag: '-p-', desc: 'Scan all 65535 TCP ports' })
      break
    case 'fast':
      items.push({ flag: '-F', desc: 'Fast scan – scan 100 most common ports' })
      break
  }

  if (c.serviceDetection) {
    items.push({ flag: '-sV', desc: 'Probe open ports to determine service/version info' })
    if (c.versionIntensity) items.push({ flag: `--version-intensity ${c.versionIntensity}`, desc: `Version detection intensity (0-9, higher = more probes, default 7)` })
  }

  if (c.osDetection) {
    items.push({ flag: '-O', desc: 'Enable OS detection via TCP/IP stack fingerprinting' })
    if (c.osGuess) items.push({ flag: '--osscan-guess', desc: 'Guess OS more aggressively when exact match unavailable' })
  }

  if (c.aggressive) items.push({ flag: '-A', desc: 'Aggressive mode: OS detection + version + scripts + traceroute' })

  if (c.defaultScripts && c.scriptCategories.length === 0 && !c.customScript) {
    items.push({ flag: '-sC', desc: 'Run default NSE scripts (equivalent to --script=default)' })
  } else {
    const scripts: string[] = []
    if (c.defaultScripts) scripts.push('default')
    scripts.push(...c.scriptCategories.filter(s => s !== 'default'))
    if (c.customScript.trim()) scripts.push(c.customScript.trim())
    if (scripts.length > 0) items.push({ flag: `--script ${scripts.join(',')}`, desc: `Run NSE scripts: ${scripts.join(', ')}` })
  }

  if (c.timing) {
    const t = TIMING_TEMPLATES.find(t => t.value === c.timing)
    if (t) items.push({ flag: c.timing, desc: t.desc })
  }

  if (c.minRate) items.push({ flag: `--min-rate ${c.minRate}`, desc: `Send at least ${c.minRate} packets per second` })
  if (c.maxRetries) items.push({ flag: `--max-retries ${c.maxRetries}`, desc: `Cap probe retransmissions to ${c.maxRetries}` })
  if (c.hostTimeout) items.push({ flag: `--host-timeout ${c.hostTimeout}`, desc: `Skip hosts that take longer than ${c.hostTimeout}` })
  if (c.scanDelay) items.push({ flag: `--scan-delay ${c.scanDelay}`, desc: `Wait ${c.scanDelay} between each probe` })

  if (c.fragment) items.push({ flag: '-f', desc: 'Fragment packets (8 bytes) to bypass firewalls/IDS' })
  if (c.decoyIps.trim()) items.push({ flag: `-D ${c.decoyIps.trim()}`, desc: 'Use decoy IPs to mask your real IP address' })
  if (c.spoofMac.trim()) items.push({ flag: `--spoof-mac ${c.spoofMac.trim()}`, desc: 'Spoof MAC address (0=random, vendor name, or specific MAC)' })
  if (c.dataLength) items.push({ flag: `--data-length ${c.dataLength}`, desc: `Append random data to packets (${c.dataLength} bytes)` })
  if (c.sourcePort) items.push({ flag: `--source-port ${c.sourcePort}`, desc: `Use specific source port number (e.g., 53 or 80 to bypass filters)` })

  if (c.verbosity === '-v') items.push({ flag: '-v', desc: 'Increase verbosity level' })
  if (c.verbosity === '-vv') items.push({ flag: '-vv', desc: 'Very verbose output' })
  if (c.verbosity === '-d') items.push({ flag: '-d', desc: 'Debug output' })

  if (c.outputFormat && c.outputFile.trim()) {
    const of = OUTPUT_FORMATS.find(o => o.value === c.outputFormat)
    if (of) items.push({ flag: `${c.outputFormat} ${c.outputFile.trim()}`, desc: of.desc })
  }

  if (c.extraFlags.trim()) items.push({ flag: c.extraFlags.trim(), desc: 'Additional custom flags' })

  if (c.target.trim()) items.push({ flag: c.target.trim(), desc: 'Target host(s) to scan' })

  return items
}

// ── Component ──────────────────────────────────────────────
export default function NmapQueryBuilder() {
  const [config, setConfig] = useState<NmapConfig>(DEFAULT_CONFIG)
  const [copied, setCopied] = useState('')
  const [activeTab, setActiveTab] = useState<'builder' | 'profiles' | 'history' | 'reference'>('builder')
  const [activeSection, setActiveSection] = useState<'basic' | 'discovery' | 'scripts' | 'performance' | 'evasion' | 'output'>('basic')
  const [customProfiles, setCustomProfiles] = useState<ScanProfile[]>(() => lsGet<ScanProfile[]>('bt_nmap_profiles', []))
  const [history, setHistory] = useState<HistoryEntry[]>(() => lsGet<HistoryEntry[]>('bt_nmap_history', []))
  const [profileName, setProfileName] = useState('')
  const [profileDesc, setProfileDesc] = useState('')
  const [showExplanation, setShowExplanation] = useState(true)

  const command = useMemo(() => buildCommand(config), [config])
  const explanation = useMemo(() => buildExplanation(config), [config])

  const update = useCallback(<K extends keyof NmapConfig>(key: K, value: NmapConfig[K]) => {
    setConfig(prev => ({ ...prev, [key]: value }))
  }, [])

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const loadProfile = (profile: ScanProfile) => {
    setConfig({ ...DEFAULT_CONFIG, target: config.target, ...profile.config })
    setActiveTab('builder')
  }

  const saveProfile = () => {
    if (!profileName.trim()) return
    const profile: ScanProfile = {
      id: Date.now().toString(),
      name: profileName.trim(),
      description: profileDesc.trim() || 'Custom profile',
      config: { ...config, target: '' },
    }
    const updated = [...customProfiles, profile]
    setCustomProfiles(updated)
    lsSet('bt_nmap_profiles', updated)
    setProfileName('')
    setProfileDesc('')
  }

  const deleteProfile = (id: string) => {
    const updated = customProfiles.filter(p => p.id !== id)
    setCustomProfiles(updated)
    lsSet('bt_nmap_profiles', updated)
  }

  const addToHistory = () => {
    if (!command || command === 'nmap') return
    const entry: HistoryEntry = {
      id: Date.now().toString(),
      command,
      timestamp: new Date().toISOString(),
      label: config.target || 'untitled',
    }
    const updated = [entry, ...history].slice(0, 50)
    setHistory(updated)
    lsSet('bt_nmap_history', updated)
  }

  const clearHistory = () => {
    setHistory([])
    lsSet('bt_nmap_history', [])
  }

  const resetConfig = () => setConfig(DEFAULT_CONFIG)

  const allProfiles = [...BUILTIN_PROFILES, ...customProfiles]

  const BUILDER_SECTIONS = [
    { id: 'basic' as const, label: 'Scan & Ports', icon: '🎯' },
    { id: 'discovery' as const, label: 'Host Discovery', icon: '📡' },
    { id: 'scripts' as const, label: 'NSE Scripts', icon: '📜' },
    { id: 'performance' as const, label: 'Performance', icon: '⚡' },
    { id: 'evasion' as const, label: 'Evasion', icon: '🛡' },
    { id: 'output' as const, label: 'Output', icon: '📄' },
  ]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">NMAP Query Builder</h2>
        <p className="section-subheading">Build, customize, and manage Nmap scan commands with a visual interface</p>
      </div>

      {/* Command Preview – always visible */}
      <div className="card" style={{ borderColor: 'rgba(0,212,255,0.15)' }}>
        <div className="flex items-center justify-between flex-wrap gap-2 mb-2">
          <span className="card-title">Generated Command</span>
          <div className="flex gap-2">
            <button onClick={() => { copy(command, 'main'); addToHistory() }} className="btn-primary text-xs py-1">
              {copied === 'main' ? '✓ Copied!' : '📋 Copy & Save'}
            </button>
            <button onClick={resetConfig} className="btn-danger text-xs py-1">Reset</button>
          </div>
        </div>
        <pre className="code-block text-sm overflow-x-auto whitespace-pre-wrap font-mono" style={{ color: '#39ff14' }}>{command}</pre>
      </div>

      {/* Tab bar */}
      <div className="flex gap-2 flex-wrap">
        {([
          { id: 'builder' as const, label: '🔧 Query Builder' },
          { id: 'profiles' as const, label: '📁 Scan Profiles' },
          { id: 'history' as const, label: '📜 History' },
          { id: 'reference' as const, label: '📖 Quick Reference' },
        ]).map(t => (
          <button key={t.id} onClick={() => setActiveTab(t.id)} className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Builder Tab ──────────────────────────────────── */}
      {activeTab === 'builder' && (
        <div className="space-y-4">
          {/* Target Input */}
          <div className="card">
            <div className="card-header"><span className="card-title">🎯 Target Specification</span></div>
            <input
              type="text"
              className="cyber-input w-full"
              value={config.target}
              onChange={e => update('target', e.target.value)}
              placeholder="e.g. 192.168.1.0/24, 10.0.0.1-50, scanme.nmap.org, or file:targets.txt"
            />
            <div className="flex gap-3 mt-2 flex-wrap">
              {[
                { label: '192.168.1.0/24', desc: 'Subnet' },
                { label: '10.0.0.1-50', desc: 'Range' },
                { label: 'scanme.nmap.org', desc: 'Hostname' },
                { label: '192.168.1.1,2,3', desc: 'List' },
              ].map(ex => (
                <button key={ex.label} onClick={() => update('target', ex.label)} className="text-xs text-gray-500 hover:text-blue-400 transition-colors">
                  <span className="text-blue-400/60">{ex.desc}:</span> <code className="text-green-400/70">{ex.label}</code>
                </button>
              ))}
            </div>
          </div>

          {/* Section tabs */}
          <div className="flex gap-1 flex-wrap">
            {BUILDER_SECTIONS.map(s => (
              <button key={s.id} onClick={() => setActiveSection(s.id)} className={`tab-btn text-xs ${activeSection === s.id ? 'active' : ''}`}>
                {s.icon} {s.label}
              </button>
            ))}
          </div>

          {/* Basic: Scan Type & Ports */}
          {activeSection === 'basic' && (
            <div className="grid md:grid-cols-2 gap-4">
              <div className="card">
                <div className="card-header"><span className="card-title">Scan Type</span></div>
                <div className="space-y-1.5">
                  {SCAN_TYPES.map(st => (
                    <label key={st.value} className="flex items-start gap-2 p-2 rounded cursor-pointer hover:bg-blue-500/5 transition-colors" style={{ border: `1px solid ${config.scanType === st.value ? 'rgba(0,212,255,0.3)' : 'transparent'}` }}>
                      <input type="radio" name="scanType" checked={config.scanType === st.value} onChange={() => update('scanType', st.value)} className="mt-1 accent-cyan-400" />
                      <div>
                        <div className="text-xs font-semibold text-gray-200"><code className="text-blue-400">{st.value}</code> {st.label}</div>
                        <div className="text-xs text-gray-500">{st.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-4">
                <div className="card">
                  <div className="card-header"><span className="card-title">Port Specification</span></div>
                  <div className="space-y-2">
                    {([
                      { value: 'default' as const, label: 'Default', desc: 'Nmap default (top 1000)' },
                      { value: 'specific' as const, label: 'Specific Ports', desc: '-p 22,80,443,8080' },
                      { value: 'range' as const, label: 'Port Range', desc: '-p 1-1024' },
                      { value: 'top' as const, label: 'Top N Ports', desc: '--top-ports N' },
                      { value: 'all' as const, label: 'All Ports', desc: '-p- (1-65535)' },
                      { value: 'fast' as const, label: 'Fast Scan', desc: '-F (top 100)' },
                    ]).map(opt => (
                      <label key={opt.value} className="flex items-center gap-2 p-1.5 rounded cursor-pointer hover:bg-blue-500/5 text-xs" style={{ border: `1px solid ${config.portOption === opt.value ? 'rgba(0,212,255,0.3)' : 'transparent'}` }}>
                        <input type="radio" name="portOption" checked={config.portOption === opt.value} onChange={() => update('portOption', opt.value)} className="accent-cyan-400" />
                        <span className="text-gray-200 font-medium">{opt.label}</span>
                        <span className="text-gray-600 ml-auto">{opt.desc}</span>
                      </label>
                    ))}
                  </div>

                  {(config.portOption === 'specific' || config.portOption === 'range') && (
                    <input
                      type="text"
                      className="cyber-input w-full mt-2"
                      value={config.specificPorts}
                      onChange={e => update('specificPorts', e.target.value)}
                      placeholder={config.portOption === 'specific' ? '22,80,443,8080,3389' : '1-1024'}
                    />
                  )}

                  {config.portOption === 'top' && (
                    <div className="flex items-center gap-2 mt-2">
                      <span className="text-xs text-gray-400">Top</span>
                      <input
                        type="number"
                        className="cyber-input w-24"
                        value={config.topPorts}
                        onChange={e => update('topPorts', e.target.value)}
                        min="1" max="65535"
                      />
                      <span className="text-xs text-gray-400">ports</span>
                    </div>
                  )}
                </div>

                <div className="card">
                  <div className="card-header"><span className="card-title">Detection Options</span></div>
                  <div className="space-y-2">
                    <label className="flex items-center gap-2 text-xs cursor-pointer">
                      <input type="checkbox" checked={config.serviceDetection} onChange={e => update('serviceDetection', e.target.checked)} className="accent-cyan-400" />
                      <span className="text-gray-200 font-medium">Service/Version Detection</span>
                      <code className="text-blue-400 ml-auto">-sV</code>
                    </label>
                    {config.serviceDetection && (
                      <div className="flex items-center gap-2 ml-5">
                        <span className="text-xs text-gray-500">Intensity:</span>
                        <select className="cyber-select text-xs" value={config.versionIntensity} onChange={e => update('versionIntensity', e.target.value)}>
                          <option value="">Default (7)</option>
                          {[0,1,2,3,4,5,6,7,8,9].map(i => <option key={i} value={String(i)}>{i} {i === 0 ? '(light)' : i === 9 ? '(all probes)' : ''}</option>)}
                        </select>
                      </div>
                    )}

                    <label className="flex items-center gap-2 text-xs cursor-pointer">
                      <input type="checkbox" checked={config.osDetection} onChange={e => update('osDetection', e.target.checked)} className="accent-cyan-400" />
                      <span className="text-gray-200 font-medium">OS Detection</span>
                      <code className="text-blue-400 ml-auto">-O</code>
                    </label>
                    {config.osDetection && (
                      <label className="flex items-center gap-2 text-xs cursor-pointer ml-5">
                        <input type="checkbox" checked={config.osGuess} onChange={e => update('osGuess', e.target.checked)} className="accent-cyan-400" />
                        <span className="text-gray-400">Aggressive OS guessing</span>
                        <code className="text-blue-400 ml-auto">--osscan-guess</code>
                      </label>
                    )}

                    <label className="flex items-center gap-2 text-xs cursor-pointer">
                      <input type="checkbox" checked={config.aggressive} onChange={e => update('aggressive', e.target.checked)} className="accent-cyan-400" />
                      <span className="text-gray-200 font-medium">Aggressive Mode</span>
                      <code className="text-blue-400 ml-auto">-A</code>
                    </label>
                    <div className="text-xs text-gray-600 ml-5">Enables OS detection, version detection, script scanning, and traceroute</div>
                  </div>

                  <div className="mt-3">
                    <div className="text-xs text-gray-400 mb-1.5">Timing Template</div>
                    <select className="cyber-select w-full text-xs" value={config.timing} onChange={e => update('timing', e.target.value)}>
                      {TIMING_TEMPLATES.map(t => (
                        <option key={t.value} value={t.value}>{t.label} – {t.desc}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Host Discovery */}
          {activeSection === 'discovery' && (
            <div className="card">
              <div className="card-header"><span className="card-title">Host Discovery Options</span></div>
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-xs cursor-pointer p-2 rounded" style={{ background: config.skipHostDiscovery ? 'rgba(255,68,68,0.08)' : 'transparent', border: `1px solid ${config.skipHostDiscovery ? 'rgba(255,68,68,0.3)' : 'transparent'}` }}>
                  <input type="checkbox" checked={config.skipHostDiscovery} onChange={e => update('skipHostDiscovery', e.target.checked)} className="accent-cyan-400" />
                  <span className="text-gray-200 font-medium">Skip Host Discovery</span>
                  <code className="text-red-400 ml-auto">-Pn</code>
                </label>
                <div className="text-xs text-gray-600 ml-5 -mt-1">Treat all hosts as online. Useful when hosts block ICMP.</div>

                {!config.skipHostDiscovery && (
                  <div className="space-y-1.5 mt-2">
                    <div className="text-xs text-gray-400 mb-1">Discovery Method</div>
                    {HOST_DISCOVERY_OPTIONS.map(hd => (
                      <label key={hd.value} className="flex items-start gap-2 p-2 rounded cursor-pointer hover:bg-blue-500/5 transition-colors" style={{ border: `1px solid ${config.hostDiscovery === hd.value ? 'rgba(0,212,255,0.3)' : 'transparent'}` }}>
                        <input type="radio" name="hostDiscovery" checked={config.hostDiscovery === hd.value} onChange={() => update('hostDiscovery', hd.value)} className="mt-0.5 accent-cyan-400" />
                        <div>
                          <div className="text-xs font-medium text-gray-200">
                            {hd.value && <code className="text-blue-400 mr-1">{hd.value}</code>}
                            {hd.label}
                          </div>
                          <div className="text-xs text-gray-500">{hd.desc}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* NSE Scripts */}
          {activeSection === 'scripts' && (
            <div className="card">
              <div className="card-header"><span className="card-title">NSE Script Engine</span></div>
              <div className="space-y-3">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input type="checkbox" checked={config.defaultScripts} onChange={e => update('defaultScripts', e.target.checked)} className="accent-cyan-400" />
                  <span className="text-gray-200 font-medium">Default Scripts</span>
                  <code className="text-blue-400 ml-auto">-sC</code>
                </label>

                <div className="text-xs text-gray-400 mt-2 mb-1">Script Categories</div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {NSE_CATEGORIES.map(cat => (
                    <label key={cat.value} className="flex items-start gap-2 p-2 rounded cursor-pointer hover:bg-blue-500/5 text-xs transition-colors" style={{ background: config.scriptCategories.includes(cat.value) ? 'rgba(0,212,255,0.05)' : 'transparent', border: `1px solid ${config.scriptCategories.includes(cat.value) ? 'rgba(0,212,255,0.3)' : 'rgba(0,212,255,0.06)'}` }}>
                      <input
                        type="checkbox"
                        checked={config.scriptCategories.includes(cat.value)}
                        onChange={e => {
                          const cats = e.target.checked
                            ? [...config.scriptCategories, cat.value]
                            : config.scriptCategories.filter(c => c !== cat.value)
                          update('scriptCategories', cats)
                        }}
                        className="mt-0.5 accent-cyan-400"
                      />
                      <div>
                        <div className="text-gray-200 font-medium">{cat.value}</div>
                        <div className="text-gray-500">{cat.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>

                <div className="mt-3">
                  <div className="text-xs text-gray-400 mb-1">Custom Script Name</div>
                  <input
                    type="text"
                    className="cyber-input w-full"
                    value={config.customScript}
                    onChange={e => update('customScript', e.target.value)}
                    placeholder="e.g. http-enum, smb-vuln-ms17-010, ssl-heartbleed"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Performance */}
          {activeSection === 'performance' && (
            <div className="card">
              <div className="card-header"><span className="card-title">Performance Tuning</span></div>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-gray-400 mb-1">Minimum Packet Rate</div>
                  <div className="flex items-center gap-2">
                    <input type="number" className="cyber-input w-full" value={config.minRate} onChange={e => update('minRate', e.target.value)} placeholder="e.g. 1000" min="1" />
                    <code className="text-blue-400 text-xs whitespace-nowrap">--min-rate</code>
                  </div>
                  <div className="text-xs text-gray-600 mt-1">Minimum packets per second</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400 mb-1">Max Retries</div>
                  <div className="flex items-center gap-2">
                    <input type="number" className="cyber-input w-full" value={config.maxRetries} onChange={e => update('maxRetries', e.target.value)} placeholder="e.g. 3" min="0" />
                    <code className="text-blue-400 text-xs whitespace-nowrap">--max-retries</code>
                  </div>
                  <div className="text-xs text-gray-600 mt-1">Limit probe retransmissions</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400 mb-1">Host Timeout</div>
                  <div className="flex items-center gap-2">
                    <input type="text" className="cyber-input w-full" value={config.hostTimeout} onChange={e => update('hostTimeout', e.target.value)} placeholder="e.g. 30m, 1h" />
                    <code className="text-blue-400 text-xs whitespace-nowrap">--host-timeout</code>
                  </div>
                  <div className="text-xs text-gray-600 mt-1">Skip hosts that exceed timeout</div>
                </div>
                <div>
                  <div className="text-xs text-gray-400 mb-1">Scan Delay</div>
                  <div className="flex items-center gap-2">
                    <input type="text" className="cyber-input w-full" value={config.scanDelay} onChange={e => update('scanDelay', e.target.value)} placeholder="e.g. 1s, 500ms" />
                    <code className="text-blue-400 text-xs whitespace-nowrap">--scan-delay</code>
                  </div>
                  <div className="text-xs text-gray-600 mt-1">Minimum delay between probes</div>
                </div>
              </div>
            </div>
          )}

          {/* Evasion */}
          {activeSection === 'evasion' && (
            <div className="card">
              <div className="card-header"><span className="card-title">Firewall / IDS Evasion</span></div>
              <div className="space-y-4">
                <label className="flex items-center gap-2 text-xs cursor-pointer">
                  <input type="checkbox" checked={config.fragment} onChange={e => update('fragment', e.target.checked)} className="accent-cyan-400" />
                  <span className="text-gray-200 font-medium">Fragment Packets</span>
                  <code className="text-blue-400 ml-auto">-f</code>
                </label>
                <div className="text-xs text-gray-600 ml-5 -mt-2">Split packets into 8-byte fragments to bypass packet inspection</div>

                <div className="grid md:grid-cols-2 gap-4">
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Decoy IPs</div>
                    <input type="text" className="cyber-input w-full" value={config.decoyIps} onChange={e => update('decoyIps', e.target.value)} placeholder="RND:5 or 10.0.0.1,10.0.0.2,ME" />
                    <div className="text-xs text-gray-600 mt-1"><code className="text-blue-400">-D</code> Cloak scan with decoy addresses. Use RND:N for random or ME for your IP.</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Spoof MAC</div>
                    <input type="text" className="cyber-input w-full" value={config.spoofMac} onChange={e => update('spoofMac', e.target.value)} placeholder="0 (random), Apple, or AA:BB:CC:DD:EE:FF" />
                    <div className="text-xs text-gray-600 mt-1"><code className="text-blue-400">--spoof-mac</code> Use 0 for random, a vendor name, or specific MAC.</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Append Data Length</div>
                    <input type="number" className="cyber-input w-full" value={config.dataLength} onChange={e => update('dataLength', e.target.value)} placeholder="e.g. 24" min="0" />
                    <div className="text-xs text-gray-600 mt-1"><code className="text-blue-400">--data-length</code> Append random bytes to make packets look less suspicious.</div>
                  </div>
                  <div>
                    <div className="text-xs text-gray-400 mb-1">Source Port</div>
                    <input type="number" className="cyber-input w-full" value={config.sourcePort} onChange={e => update('sourcePort', e.target.value)} placeholder="e.g. 53, 80" min="1" max="65535" />
                    <div className="text-xs text-gray-600 mt-1"><code className="text-blue-400">--source-port</code> Use port 53 or 80 to bypass poorly configured firewalls.</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Output */}
          {activeSection === 'output' && (
            <div className="card">
              <div className="card-header"><span className="card-title">Output & Verbosity</span></div>
              <div className="grid md:grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-gray-400 mb-1.5">Output Format</div>
                  <div className="space-y-1.5">
                    {OUTPUT_FORMATS.map(of => (
                      <label key={of.value} className="flex items-center gap-2 p-1.5 rounded cursor-pointer hover:bg-blue-500/5 text-xs" style={{ border: `1px solid ${config.outputFormat === of.value ? 'rgba(0,212,255,0.3)' : 'transparent'}` }}>
                        <input type="radio" name="outputFormat" checked={config.outputFormat === of.value} onChange={() => update('outputFormat', of.value)} className="accent-cyan-400" />
                        <span className="text-gray-200 font-medium">{of.label}</span>
                        <span className="text-gray-600 ml-auto">{of.desc}</span>
                      </label>
                    ))}
                  </div>

                  {config.outputFormat && (
                    <div className="mt-2">
                      <div className="text-xs text-gray-400 mb-1">Output Filename</div>
                      <input type="text" className="cyber-input w-full" value={config.outputFile} onChange={e => update('outputFile', e.target.value)} placeholder="scan_results" />
                    </div>
                  )}
                </div>

                <div className="space-y-4">
                  <div>
                    <div className="text-xs text-gray-400 mb-1.5">Verbosity</div>
                    <select className="cyber-select w-full text-xs" value={config.verbosity} onChange={e => update('verbosity', e.target.value)}>
                      <option value="">Normal</option>
                      <option value="-v">Verbose (-v)</option>
                      <option value="-vv">Very Verbose (-vv)</option>
                      <option value="-d">Debug (-d)</option>
                    </select>
                  </div>

                  <div>
                    <div className="text-xs text-gray-400 mb-1.5">Extra Flags</div>
                    <input type="text" className="cyber-input w-full" value={config.extraFlags} onChange={e => update('extraFlags', e.target.value)} placeholder="e.g. --traceroute --reason --open" />
                    <div className="text-xs text-gray-600 mt-1">Append any additional nmap flags not covered above</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Command Explanation */}
          <div className="card">
            <div className="flex items-center justify-between">
              <span className="card-title">Command Breakdown</span>
              <button onClick={() => setShowExplanation(!showExplanation)} className="text-xs text-blue-400">{showExplanation ? 'Hide' : 'Show'}</button>
            </div>
            {showExplanation && (
              <div className="mt-3 space-y-1">
                {explanation.map((item, i) => (
                  <div key={i} className="flex items-start gap-3 py-1.5" style={{ borderBottom: '1px solid rgba(0,212,255,0.04)' }}>
                    <code className="text-xs text-green-400 font-mono shrink-0 min-w-[140px]">{item.flag}</code>
                    <span className="text-xs text-gray-400">{item.desc}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Profiles Tab ─────────────────────────────────── */}
      {activeTab === 'profiles' && (
        <div className="space-y-4">
          {/* Save current config as profile */}
          <div className="card">
            <div className="card-header"><span className="card-title">💾 Save Current Configuration as Profile</span></div>
            <div className="grid md:grid-cols-2 gap-3">
              <input type="text" className="cyber-input" value={profileName} onChange={e => setProfileName(e.target.value)} placeholder="Profile name" />
              <input type="text" className="cyber-input" value={profileDesc} onChange={e => setProfileDesc(e.target.value)} placeholder="Description (optional)" />
            </div>
            <button onClick={saveProfile} disabled={!profileName.trim()} className="btn-primary text-xs mt-3 disabled:opacity-50">Save Profile</button>
          </div>

          {/* Built-in profiles */}
          <div className="card">
            <div className="card-header"><span className="card-title">📦 Built-in Profiles</span></div>
            <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
              {BUILTIN_PROFILES.map(p => (
                <button
                  key={p.id}
                  onClick={() => loadProfile(p)}
                  className="text-left p-3 rounded-lg transition-all hover:scale-[1.01]"
                  style={{ background: 'rgba(10,20,40,0.6)', border: '1px solid rgba(0,212,255,0.1)' }}
                >
                  <div className="text-xs font-semibold text-blue-400 mb-1">{p.name}</div>
                  <div className="text-xs text-gray-500">{p.description}</div>
                  <div className="text-xs text-gray-600 mt-2 font-mono truncate">{buildCommand({ ...DEFAULT_CONFIG, ...p.config, target: '<target>' })}</div>
                </button>
              ))}
            </div>
          </div>

          {/* Custom profiles */}
          {customProfiles.length > 0 && (
            <div className="card">
              <div className="card-header"><span className="card-title">👤 Custom Profiles</span></div>
              <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
                {customProfiles.map(p => (
                  <div key={p.id} className="p-3 rounded-lg" style={{ background: 'rgba(10,20,40,0.6)', border: '1px solid rgba(0,212,255,0.1)' }}>
                    <div className="text-xs font-semibold text-green-400 mb-1">{p.name}</div>
                    <div className="text-xs text-gray-500 mb-2">{p.description}</div>
                    <div className="text-xs text-gray-600 font-mono truncate mb-2">{buildCommand({ ...DEFAULT_CONFIG, ...p.config, target: '<target>' })}</div>
                    <div className="flex gap-2">
                      <button onClick={() => loadProfile(p)} className="btn-primary text-xs py-1">Load</button>
                      <button onClick={() => deleteProfile(p.id)} className="btn-danger text-xs py-1">Delete</button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Export/Import */}
          <div className="card">
            <div className="card-header"><span className="card-title">📤 Export Profiles</span></div>
            <button onClick={() => downloadJSON(customProfiles, 'nmap-profiles.json')} disabled={customProfiles.length === 0} className="btn-primary text-xs disabled:opacity-50">
              Export Custom Profiles as JSON
            </button>
          </div>
        </div>
      )}

      {/* ── History Tab ───────────────────────────────────── */}
      {activeTab === 'history' && (
        <div className="card">
          <div className="flex items-center justify-between mb-3">
            <span className="card-title">📜 Command History</span>
            {history.length > 0 && <button onClick={clearHistory} className="btn-danger text-xs py-1">Clear All</button>}
          </div>
          {history.length === 0 ? (
            <div className="text-center text-xs text-gray-500 py-8">No commands in history. Use &quot;Copy &amp; Save&quot; to add commands.</div>
          ) : (
            <div className="space-y-2">
              {history.map(h => (
                <div key={h.id} className="p-3 rounded-lg" style={{ background: 'rgba(10,20,40,0.6)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className="text-xs text-gray-400">{new Date(h.timestamp).toLocaleString()}</span>
                    <span className="text-xs text-gray-600">Target: {h.label}</span>
                  </div>
                  <pre className="text-xs font-mono text-green-400 overflow-x-auto whitespace-pre-wrap">{h.command}</pre>
                  <button onClick={() => copy(h.command, `hist-${h.id}`)} className="text-xs text-blue-400 hover:underline mt-1">
                    {copied === `hist-${h.id}` ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Reference Tab ────────────────────────────────── */}
      {activeTab === 'reference' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header"><span className="card-title">📖 Nmap Quick Reference</span></div>
            <div className="grid md:grid-cols-2 gap-4">
              <RefCard title="Target Specification" items={[
                { cmd: 'nmap 192.168.1.1', desc: 'Single host' },
                { cmd: 'nmap 192.168.1.0/24', desc: 'CIDR subnet' },
                { cmd: 'nmap 192.168.1.1-50', desc: 'IP range' },
                { cmd: 'nmap -iL targets.txt', desc: 'From file' },
                { cmd: 'nmap --exclude 192.168.1.1', desc: 'Exclude host' },
                { cmd: 'nmap 192.168.1.0/24 --excludefile ex.txt', desc: 'Exclude from file' },
              ]} onCopy={copy} copied={copied} />

              <RefCard title="Common Scan Types" items={[
                { cmd: 'nmap -sS target', desc: 'SYN scan (stealth, default root)' },
                { cmd: 'nmap -sT target', desc: 'TCP connect scan' },
                { cmd: 'nmap -sU target', desc: 'UDP scan' },
                { cmd: 'nmap -sn target', desc: 'Ping sweep (no port scan)' },
                { cmd: 'nmap -sV target', desc: 'Service version detection' },
                { cmd: 'nmap -O target', desc: 'OS detection' },
              ]} onCopy={copy} copied={copied} />

              <RefCard title="Port Selection" items={[
                { cmd: 'nmap -p 22,80,443 target', desc: 'Specific ports' },
                { cmd: 'nmap -p 1-1024 target', desc: 'Port range' },
                { cmd: 'nmap -p- target', desc: 'All 65535 ports' },
                { cmd: 'nmap -F target', desc: 'Fast scan (top 100)' },
                { cmd: 'nmap --top-ports 200 target', desc: 'Top N ports' },
                { cmd: 'nmap -p U:53,T:80 target', desc: 'Protocol-specific ports' },
              ]} onCopy={copy} copied={copied} />

              <RefCard title="Popular Combinations" items={[
                { cmd: 'nmap -sS -sV -O -A target', desc: 'Full comprehensive scan' },
                { cmd: 'nmap -sS -sC -sV -p- target', desc: 'All ports with scripts' },
                { cmd: 'nmap -sU --top-ports 20 target', desc: 'Quick UDP check' },
                { cmd: 'nmap -Pn -sS -T4 -F target', desc: 'Fast scan, skip ping' },
                { cmd: 'nmap --script vuln target', desc: 'Vulnerability scan' },
                { cmd: 'nmap -sn 192.168.1.0/24', desc: 'Network host discovery' },
              ]} onCopy={copy} copied={copied} />

              <RefCard title="NSE Scripts" items={[
                { cmd: 'nmap --script=default target', desc: 'Default scripts (-sC)' },
                { cmd: 'nmap --script=vuln target', desc: 'All vulnerability scripts' },
                { cmd: 'nmap --script=safe target', desc: 'Safe scripts only' },
                { cmd: 'nmap --script=smb-vuln* target', desc: 'Wildcard script match' },
                { cmd: 'nmap --script=http-enum target', desc: 'HTTP directory enum' },
                { cmd: 'nmap --script=ssl-heartbleed target', desc: 'Heartbleed check' },
              ]} onCopy={copy} copied={copied} />

              <RefCard title="Evasion & Performance" items={[
                { cmd: 'nmap -f target', desc: 'Fragment packets' },
                { cmd: 'nmap -D RND:5 target', desc: 'Decoy scan (5 random)' },
                { cmd: 'nmap -T0 target', desc: 'Paranoid timing' },
                { cmd: 'nmap --spoof-mac 0 target', desc: 'Random MAC address' },
                { cmd: 'nmap --data-length 24 target', desc: 'Pad packet data' },
                { cmd: 'nmap --min-rate 1000 target', desc: 'Fast minimum rate' },
              ]} onCopy={copy} copied={copied} />
            </div>
          </div>

          {/* Output examples */}
          <div className="card">
            <div className="card-header"><span className="card-title">💡 Tips & Best Practices</span></div>
            <div className="space-y-2 text-xs text-gray-400">
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Always get proper authorization before scanning networks or hosts you don&apos;t own</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Use <code className="text-green-400">-Pn</code> when scanning hosts that block ICMP ping</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Start with a quick scan (<code className="text-green-400">-F</code> or <code className="text-green-400">--top-ports 100</code>) then expand to full port scans</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Use <code className="text-green-400">-oA</code> to save results in all formats for later analysis</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Combine <code className="text-green-400">-sV</code> with <code className="text-green-400">-sC</code> for the most useful service information</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>For large networks, use <code className="text-green-400">-T4</code> with <code className="text-green-400">--min-rate</code> to speed up scans</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>UDP scans (<code className="text-green-400">-sU</code>) are slower — limit to top ports with <code className="text-green-400">--top-ports</code></span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Use XML output (<code className="text-green-400">-oX</code>) to import results into tools like Metasploit or Nessus</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Run Nmap with <code className="text-green-400">sudo</code> for SYN scans and OS detection (requires raw sockets)</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Use <code className="text-green-400">--reason</code> flag to see why Nmap classifies each port&apos;s state</span></div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Reference Card subcomponent ────────────────────────────
function RefCard({ title, items, onCopy, copied }: {
  title: string
  items: { cmd: string; desc: string }[]
  onCopy: (text: string, key: string) => void
  copied: string
}) {
  return (
    <div className="rounded-lg p-3" style={{ background: 'rgba(10,20,40,0.6)', border: '1px solid rgba(0,212,255,0.08)' }}>
      <div className="text-xs font-semibold text-blue-400 mb-2">{title}</div>
      <div className="space-y-1.5">
        {items.map((item, i) => (
          <div key={i} className="flex items-start justify-between gap-2 py-1" style={{ borderBottom: '1px solid rgba(0,212,255,0.04)' }}>
            <div className="flex-1 min-w-0">
              <code className="text-xs font-mono text-green-400 break-all">{item.cmd}</code>
              <div className="text-xs text-gray-500">{item.desc}</div>
            </div>
            <button onClick={() => onCopy(item.cmd, `ref-${title}-${i}`)} className="text-xs text-blue-400 hover:underline shrink-0">
              {copied === `ref-${title}-${i}` ? '✓' : '⧉'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}
