'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

interface TrafficPattern {
  name: string
  indicator: string[]
  description: string
  response: string[]
  query: string
}

const TRAFFIC_PATTERNS: TrafficPattern[] = [
  {
    name: 'Port Scanning',
    indicator: ['Many connection attempts to different ports from single IP', 'TCP SYN packets without completing handshake', 'RST/ACK responses from multiple ports'],
    description: 'Systematic probing of ports to identify open services. Often a precursor to exploitation.',
    response: ['Block scanning source IP at firewall', 'Alert on >20 distinct ports from single IP/minute', 'Enable port scan detection on IDS/IPS'],
    query: `// Zeek: Detect port scans
index=zeek sourcetype="zeek_conn"
| stats dc(id.resp_p) as ports by id.orig_h
| where ports > 20
| sort -ports`
  },
  {
    name: 'C2 Beaconing',
    indicator: ['Regular periodic connections to external IP/domain', 'Low jitter in connection intervals (<10%)', 'Consistent data transfer sizes', 'Connections to recently registered domains'],
    description: 'Malware checking in with command & control server at regular intervals.',
    response: ['Block identified C2 IP/domain at firewall and proxy', 'Isolate infected host immediately', 'Capture traffic sample for analysis'],
    query: `// Detect beaconing via connection regularity
index=proxy
| bucket _time span=5m
| stats count by _time, src_ip, dest_host
| eventstats avg(count) as avg, stdev(count) as stddev by src_ip, dest_host
| eval jitter = stddev/avg
| where jitter < 0.1 AND avg > 1`
  },
  {
    name: 'DNS Tunneling',
    indicator: ['Unusually long DNS query names (>50 chars)', 'High volume of DNS TXT queries', 'Subdomain enumeration patterns', 'Queries to unusual TLDs', 'DNS responses with large payloads'],
    description: 'Data exfiltration or C2 communications encoded in DNS queries/responses.',
    response: ['Block DNS to all servers except authorized DNS servers', 'Enable DNS monitoring and anomaly detection', 'Analyze queries to identify tunneling tools (iodine, dnscat2)'],
    query: `// Detect DNS tunneling
index=dns
| eval qlen=len(query)
| where qlen > 50
| stats count avg(qlen) as avg_len dc(query) as unique_q by src_ip
| where count > 100 OR avg_len > 60`
  },
  {
    name: 'Large Data Exfiltration',
    indicator: ['Unusually large outbound transfers', 'Uploads to cloud storage (dropbox, drive, pastebin)', 'High volume to single external destination', 'Traffic over non-standard ports', 'Data transfer outside business hours'],
    description: 'Theft of sensitive data from the organization to external destinations.',
    response: ['Block suspicious destination immediately', 'Capture and analyze transferred data if possible', 'Notify legal/privacy team for potential breach notification'],
    query: `// Detect large outbound transfers
index=proxy OR index=netflow
| stats sum(bytes_out) as total by src_ip, dest_host
| where total > 104857600 // 100MB
| eval GB = round(total/1073741824, 2)
| where NOT cidrmatch("10.0.0.0/8", dest_host)`
  },
  {
    name: 'Lateral Movement via SMB',
    indicator: ['SMB connections from workstations to servers (unusual flow)', 'psexec.exe or similar tool execution', 'Authentication to multiple internal hosts in short window', 'Pass-the-Hash patterns (NTLM auth without password change)'],
    description: 'Attacker moving through internal network using compromised credentials via SMB/ADMIN$.',
    response: ['Isolate source system immediately', 'Reset all accounts used in movement', 'Enable SMB signing to prevent relay attacks', 'Audit all systems the attacker touched'],
    query: `// Detect lateral movement via SMB
index=windows EventCode=4624 Logon_Type=3
| stats dc(dest_host) as hosts by src_ip, user
| where hosts > 3
| sort -hosts`
  },
  {
    name: 'Suspicious Outbound HTTPS',
    indicator: ['New SSL/TLS connections to untrusted certificates', 'Short-lived TLS sessions with repeated reconnects', 'SNI field containing long random-looking domains (DGA)', 'Connections to IPs without valid hostname'],
    description: 'Attackers increasingly use HTTPS to evade detection. SSL inspection is required to analyze.',
    response: ['Enable SSL/TLS inspection at proxy', 'Block connections to IPs without valid SNI', 'Implement certificate transparency monitoring'],
    query: `// Detect suspicious HTTPS by destination type
index=proxy
| where proto="HTTPS"
| stats count by dest_host, dest_ip, src_ip
| lookup geo_ip ip as dest_ip OUTPUT country
| where count < 5 AND country NOT IN ("US", "GB", "CA", "AU")`
  },
]

const TOOLS_REFERENCE = [
  { name: 'Wireshark', purpose: 'Packet capture and deep inspection', usage: 'wireshark -i eth0 -f "tcp port 80"', os: 'All', free: true },
  { name: 'tcpdump', purpose: 'Command-line packet capture', usage: 'tcpdump -i eth0 -w capture.pcap host 10.0.0.1', os: 'Linux/Mac', free: true },
  { name: 'Zeek (Bro)', purpose: 'Network security monitoring framework', usage: 'zeek -i eth0 local', os: 'Linux', free: true },
  { name: 'Suricata', purpose: 'IDS/IPS with protocol analysis', usage: 'suricata -c /etc/suricata/suricata.yaml -i eth0', os: 'Linux', free: true },
  { name: 'ntopng', purpose: 'Network traffic analysis', usage: 'ntopng -i eth0', os: 'Linux', free: true },
  { name: 'NetworkMiner', purpose: 'PCAP analysis and host profiling', usage: 'GUI-based PCAP analyzer', os: 'Windows', free: true },
  { name: 'tshark', purpose: 'CLI Wireshark for automation', usage: 'tshark -r capture.pcap -Y "http" -T fields -e http.request.uri', os: 'All', free: true },
  { name: 'nmap', purpose: 'Network discovery and port scanning', usage: 'nmap -sV -sC -O -A 192.168.1.0/24', os: 'All', free: true },
  { name: 'masscan', purpose: 'Fast port scanner', usage: 'masscan -p1-65535 192.168.1.0/24 --rate=1000', os: 'Linux', free: true },
  { name: 'Arkime (Moloch)', purpose: 'Full packet capture storage and search', usage: 'arkime-capture -i eth0', os: 'Linux', free: true },
]

const COMMON_FILTERS: { desc: string; filter: string; tool: string }[] = [
  { tool: 'Wireshark/tshark', desc: 'Show only HTTP traffic', filter: 'http' },
  { tool: 'Wireshark/tshark', desc: 'Filter by source IP', filter: 'ip.src == 192.168.1.100' },
  { tool: 'Wireshark/tshark', desc: 'Filter by destination port', filter: 'tcp.dstport == 443' },
  { tool: 'Wireshark/tshark', desc: 'Show DNS queries', filter: 'dns.flags.response == 0' },
  { tool: 'Wireshark/tshark', desc: 'Large packets (possible exfil)', filter: 'frame.len > 1400' },
  { tool: 'Wireshark/tshark', desc: 'TCP SYN packets (scan)', filter: 'tcp.flags.syn == 1 && tcp.flags.ack == 0' },
  { tool: 'Wireshark/tshark', desc: 'HTTP POST requests', filter: 'http.request.method == "POST"' },
  { tool: 'Wireshark/tshark', desc: 'Follow TCP stream', filter: 'tcp.stream eq <N>' },
  { tool: 'tcpdump', desc: 'Capture port 80 traffic', filter: '-i eth0 -s 0 port 80' },
  { tool: 'tcpdump', desc: 'Capture specific host traffic', filter: '-i eth0 host 10.0.0.55' },
  { tool: 'tcpdump', desc: 'Capture UDP DNS traffic', filter: '-i eth0 udp port 53' },
  { tool: 'tcpdump', desc: 'Write PCAP with rotation', filter: '-i eth0 -w /tmp/cap-%Y%m%d%H%M%S.pcap -G 3600' },
]

export default function NetworkAnalysis() {
  const [selectedPattern, setSelectedPattern] = useState(0)
  const [activeTab, setActiveTab] = useState<'patterns' | 'tools' | 'filters'>('patterns')
  const [copied, setCopied] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const pattern = TRAFFIC_PATTERNS[selectedPattern]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Network Analysis</h2>
        <p className="section-subheading">Traffic pattern analysis, network forensics tools, and detection queries</p>
      </div>

      <div className="flex gap-2 flex-wrap">
        {(['patterns', 'tools', 'filters'] as const).map(t => (
          <button key={t} onClick={() => setActiveTab(t)} className={`tab-btn ${activeTab === t ? 'active' : ''}`}>
            {t === 'patterns' ? '🌐 Traffic Patterns' : t === 'tools' ? '🛠 Tools Reference' : '🔍 Capture Filters'}
          </button>
        ))}
      </div>

      {activeTab === 'patterns' && (
        <div className="grid md:grid-cols-3 gap-4">
          <div className="space-y-2">
            {TRAFFIC_PATTERNS.map((p, i) => (
              <button
                key={i}
                onClick={() => setSelectedPattern(i)}
                className="w-full text-left p-3 rounded-lg transition-all"
                style={{ background: 'rgba(10,20,40,0.6)', border: `1px solid ${selectedPattern === i ? 'rgba(0,212,255,0.4)' : 'rgba(0,212,255,0.08)'}` }}
              >
                <div className="text-sm font-medium text-gray-200">{p.name}</div>
              </button>
            ))}
          </div>

          <div className="md:col-span-2 space-y-4">
            <div className="card">
              <div className="text-base font-semibold text-blue-300 mb-2">{pattern.name}</div>
              <p className="text-sm text-gray-400 mb-4">{pattern.description}</p>

              <div className="mb-4">
                <div className="text-xs font-semibold text-yellow-400 mb-2">⚠ Indicators</div>
                <ul className="space-y-1">
                  {pattern.indicator.map((ind, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
                      <span className="text-yellow-400 shrink-0">▸</span> {ind}
                    </li>
                  ))}
                </ul>
              </div>

              <div className="mb-4">
                <div className="text-xs font-semibold text-green-400 mb-2">✓ Response Actions</div>
                <ul className="space-y-1">
                  {pattern.response.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
                      <span className="text-green-400 shrink-0">{i + 1}.</span> {r}
                    </li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="card-title">Detection Query (Splunk)</span>
                <button onClick={() => copy(pattern.query, 'net-query')} className="btn-primary text-xs py-1">
                  {copied === 'net-query' ? '✓ Copied' : 'Copy'}
                </button>
              </div>
              <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{pattern.query}</pre>
            </div>
          </div>
        </div>
      )}

      {activeTab === 'tools' && (
        <div className="card overflow-x-auto">
          <table className="cyber-table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Purpose</th>
                <th>OS</th>
                <th>Free</th>
                <th>Usage Example</th>
                <th>Copy</th>
              </tr>
            </thead>
            <tbody>
              {TOOLS_REFERENCE.map(tool => (
                <tr key={tool.name}>
                  <td className="font-semibold text-blue-400">{tool.name}</td>
                  <td className="text-xs">{tool.purpose}</td>
                  <td className="text-xs">{tool.os}</td>
                  <td>{tool.free ? <span className="badge badge-success">Free</span> : <span className="badge badge-medium">Paid</span>}</td>
                  <td><code className="text-xs font-mono text-green-400">{tool.usage}</code></td>
                  <td>
                    <button onClick={() => copy(tool.usage, `tool-${tool.name}`)} className="text-xs text-blue-400 hover:underline">
                      {copied === `tool-${tool.name}` ? '✓' : '⧉'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {activeTab === 'filters' && (
        <div className="space-y-4">
          <div className="grid md:grid-cols-2 gap-4">
            {['Wireshark/tshark', 'tcpdump'].map(toolName => (
              <div key={toolName} className="card">
                <div className="card-header"><span className="card-title">{toolName} Filters</span></div>
                <div className="space-y-2">
                  {COMMON_FILTERS.filter(f => f.tool === toolName).map((f, i) => (
                    <div key={i} className="flex items-center gap-2 py-2 border-b" style={{ borderColor: 'rgba(0,212,255,0.06)' }}>
                      <div className="flex-1">
                        <div className="text-xs text-gray-400">{f.desc}</div>
                        <code className="text-xs font-mono text-green-400">{f.filter}</code>
                      </div>
                      <button onClick={() => copy(f.filter, `filter-${toolName}-${i}`)} className="text-xs text-blue-400 hover:underline shrink-0">
                        {copied === `filter-${toolName}-${i}` ? '✓' : '⧉'}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* PCAP analysis workflow */}
          <div className="card">
            <div className="card-header"><span className="card-title">PCAP Analysis Workflow</span></div>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <div className="text-xs font-semibold text-blue-400 mb-2">Step 1: Initial Triage</div>
                <div className="code-block text-xs">
{`# Get capture statistics
capinfos capture.pcap

# Quick protocol breakdown
tshark -r capture.pcap -q -z io,phs

# Export HTTP objects
tshark -r capture.pcap --export-objects http,/tmp/http_exports

# List all unique conversations
tshark -r capture.pcap -q -z conv,tcp`}
                </div>
              </div>
              <div>
                <div className="text-xs font-semibold text-blue-400 mb-2">Step 2: Extract Artifacts</div>
                <div className="code-block text-xs">
{`# Extract DNS queries
tshark -r capture.pcap -Y dns -T fields -e dns.qry.name | sort -u

# Extract all URLs
tshark -r capture.pcap -Y http.request -T fields \\
  -e http.host -e http.request.uri | sort -u

# Extract user agents
tshark -r capture.pcap -Y http.user_agent -T fields \\
  -e http.user_agent | sort | uniq -c | sort -rn

# Extract TLS SNI
tshark -r capture.pcap -Y ssl.handshake.extensions_server_name \\
  -T fields -e ssl.handshake.extensions_server_name | sort -u`}
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
