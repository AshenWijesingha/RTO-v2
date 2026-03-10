'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

interface QueryTemplate {
  id: string
  name: string
  category: string
  splunk: string
  elastic: string
  kql: string
  description: string
}

const TEMPLATES: QueryTemplate[] = [
  {
    id: 'failed-logins',
    name: 'Failed Login Attempts',
    category: 'Authentication',
    description: 'Detect multiple failed login attempts (brute force / password spray)',
    splunk: `index=windows EventCode=4625
| stats count by src_ip, user, dest_host
| where count > 5
| sort -count
| eval Risk = if(count > 20, "HIGH", if(count > 10, "MEDIUM", "LOW"))
| table src_ip, user, dest_host, count, Risk`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "winlog.event_id": 4625 } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ]
    }
  },
  "aggs": {
    "by_ip": {
      "terms": { "field": "source.ip", "size": 20 }
    }
  }
}`,
    kql: `SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by IpAddress, Account, Computer
| where FailedAttempts > 5
| sort by FailedAttempts desc
| extend Risk = iff(FailedAttempts > 20, "HIGH", iff(FailedAttempts > 10, "MEDIUM", "LOW"))`,
  },
  {
    id: 'lateral-movement',
    name: 'Lateral Movement Detection',
    category: 'Lateral Movement',
    description: 'Detect lateral movement via PsExec, WMI, or SMB',
    splunk: `index=windows (EventCode=4648 OR EventCode=4624)
| eval src=coalesce(src_ip, src_host)
| where EventCode=4624 AND Logon_Type IN (3,10)
| stats count dc(dest_host) as unique_hosts by src, user
| where unique_hosts > 3
| sort -unique_hosts`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4648, 4624] } },
        { "range": { "@timestamp": { "gte": "now-4h" } } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID in (4648, 4624)
| where LogonType in (3, 10)
| where TimeGenerated > ago(4h)
| summarize UniqueHosts = dcount(Computer), Count = count() by Account, IpAddress
| where UniqueHosts > 3
| sort by UniqueHosts desc`,
  },
  {
    id: 'powershell-suspicious',
    name: 'Suspicious PowerShell',
    category: 'Execution',
    description: 'Detect suspicious PowerShell execution patterns (encoded commands, download cradles)',
    splunk: `index=windows source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
  (EventCode=4104 OR EventCode=4103)
| where match(Message, "(?i)(invoke-expression|iex|downloadstring|webclient|encodedcommand|-enc|-w hidden|bypass|mimikatz|powersploit)")
| eval Severity=case(
    match(Message,"(?i)mimikatz|powersploit"), "CRITICAL",
    match(Message,"(?i)downloadstring|webclient"), "HIGH",
    true(), "MEDIUM")
| table _time, host, user, Message, Severity
| sort -_time`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4104, 4103] } }
      ],
      "should": [
        { "match_phrase": { "message": "invoke-expression" } },
        { "match_phrase": { "message": "DownloadString" } },
        { "match_phrase": { "message": "encodedcommand" } },
        { "match_phrase": { "message": "bypass" } }
      ],
      "minimum_should_match": 1
    }
  }
}`,
    kql: `Event
| where Source == "Microsoft-Windows-PowerShell"
| where EventID in (4104, 4103)
| where TimeGenerated > ago(24h)
| where RenderedDescription has_any ("Invoke-Expression", "DownloadString", "EncodedCommand", "bypass", "hidden", "mimikatz")
| extend Severity = case(
    RenderedDescription has_any ("mimikatz", "powersploit"), "CRITICAL",
    RenderedDescription has_any ("DownloadString", "WebClient"), "HIGH",
    "MEDIUM")
| project TimeGenerated, Computer, UserName, RenderedDescription, Severity
| sort by TimeGenerated desc`,
  },
  {
    id: 'ransomware-activity',
    name: 'Ransomware Activity',
    category: 'Ransomware',
    description: 'Detect potential ransomware via rapid file modifications',
    splunk: `index=windows EventCode=4663 Object_Type=File
| eval file_ext=lower(replace(Object_Name, ".*\.", ""))
| where file_ext IN ("encrypted","locked","enc","crypto","crypt","locky","zepto","odin","aesir","thor","zzz")
    OR match(Object_Name, "(?i)(readme|recover|decrypt|ransom|how_to)")
| stats count, values(Object_Name) as files by host, user, _time span=1m
| where count > 20
| sort -count`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "winlog.event_id": 4663 } },
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "should": [
        { "wildcard": { "winlog.event_data.ObjectName": "*.encrypted" } },
        { "wildcard": { "winlog.event_data.ObjectName": "*README*" } },
        { "wildcard": { "winlog.event_data.ObjectName": "*DECRYPT*" } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID == 4663
| where ObjectType == "File"
| where TimeGenerated > ago(1h)
| where ObjectName has_any (".encrypted", ".locked", ".crypt", "README", "DECRYPT", "RANSOM")
| summarize FileCount = count(), Files = make_set(ObjectName, 10) by Account, Computer, bin(TimeGenerated, 1m)
| where FileCount > 20
| sort by FileCount desc`,
  },
  {
    id: 'dns-tunneling',
    name: 'DNS Tunneling Detection',
    category: 'Exfiltration',
    description: 'Detect potential DNS tunneling via high query volume or long domain names',
    splunk: `index=dns
| eval domain_len=len(query)
| eval subdomain_depth=mvcount(split(query,"."))
| where domain_len > 50 OR subdomain_depth > 5
| stats count, avg(domain_len) as avg_len, dc(query) as unique_domains by src_ip
| where count > 100 OR avg_len > 60
| sort -count`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "term": { "type": "dns" } },
        { "range": { "@timestamp": { "gte": "now-1h" } } },
        { "range": { "dns.question.name.length": { "gte": 50 } } }
      ]
    }
  },
  "aggs": {
    "by_source": {
      "terms": { "field": "source.ip", "size": 20 }
    }
  }
}`,
    kql: `DnsEvents
| where TimeGenerated > ago(1h)
| extend DomainLength = strlen(Name)
| extend SubdomainDepth = array_length(split(Name, "."))
| where DomainLength > 50 or SubdomainDepth > 5
| summarize QueryCount = count(), AvgDomainLen = avg(DomainLength), UniqueDomains = dcount(Name) by ClientIP
| where QueryCount > 100 or AvgDomainLen > 60
| sort by QueryCount desc`,
  },
  {
    id: 'privilege-escalation',
    name: 'Privilege Escalation',
    category: 'Privilege Escalation',
    description: 'Detect user privilege escalation events',
    splunk: `index=windows (EventCode=4728 OR EventCode=4732 OR EventCode=4756 OR EventCode=4672)
| eval group_name=coalesce(Group_Name, MemberName)
| where group_name IN ("Administrators","Domain Admins","Enterprise Admins","Schema Admins","Account Operators")
| table _time, EventCode, host, user, group_name, src_ip
| sort -_time`,
    elastic: `GET /winlogbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "terms": { "winlog.event_id": [4728, 4732, 4756, 4672] } },
        { "range": { "@timestamp": { "gte": "now-24h" } } }
      ]
    }
  }
}`,
    kql: `SecurityEvent
| where EventID in (4728, 4732, 4756, 4672)
| where TimeGenerated > ago(24h)
| where TargetUserName has_any ("Administrators", "Domain Admins", "Enterprise Admins")
    or Activity has "special privileges"
| project TimeGenerated, Activity, SubjectAccount, TargetAccount, TargetUserName, Computer, IpAddress
| sort by TimeGenerated desc`,
  },
  {
    id: 'data-exfiltration',
    name: 'Data Exfiltration',
    category: 'Exfiltration',
    description: 'Detect large data transfers to external destinations',
    splunk: `index=network
| stats sum(bytes_out) as total_bytes by src_ip, dest_ip, dest_port
| where total_bytes > 104857600
| eval MB = round(total_bytes/1048576, 2)
| where NOT cidrmatch("10.0.0.0/8", dest_ip)
    AND NOT cidrmatch("172.16.0.0/12", dest_ip)
    AND NOT cidrmatch("192.168.0.0/16", dest_ip)
| sort -MB
| table src_ip, dest_ip, dest_port, MB`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-1h" } } }
      ],
      "must_not": [
        { "cidr": { "network.destination.ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] } }
      ]
    }
  },
  "aggs": {
    "by_src": {
      "terms": { "field": "source.ip" },
      "aggs": { "total_bytes": { "sum": { "field": "network.bytes" } } }
    }
  }
}`,
    kql: `AzureNetworkAnalytics_CL
| where TimeGenerated > ago(1h)
| where SubType_s == "FlowLog"
| where not(ipv4_is_private(DestIP_s))
| summarize TotalBytesSent = sum(OutboundBytes_d) by SrcIP_s, DestIP_s, DestPort_d
| where TotalBytesSent > 104857600
| extend MB = round(TotalBytesSent / 1048576, 2)
| sort by MB desc`,
  },
  {
    id: 'c2-beaconing',
    name: 'C2 Beaconing Detection',
    category: 'Command & Control',
    description: 'Detect regular beaconing patterns typical of C2 malware',
    splunk: `index=proxy OR index=network
| bucket _time span=5m
| stats count by _time, src_ip, dest_ip, dest_port
| eventstats avg(count) as avg_count, stdev(count) as std_count by src_ip, dest_ip
| eval jitter = std_count / avg_count
| where jitter < 0.1 AND avg_count > 1
| stats count as beacon_intervals, avg(jitter) as avg_jitter by src_ip, dest_ip, dest_port
| where beacon_intervals > 12
| sort -beacon_intervals`,
    elastic: `GET /packetbeat-*/_search
{
  "query": {
    "bool": {
      "must": [
        { "range": { "@timestamp": { "gte": "now-6h" } } }
      ]
    }
  },
  "aggs": {
    "by_connection": {
      "composite": {
        "sources": [
          { "src": { "terms": { "field": "source.ip" } } },
          { "dst": { "terms": { "field": "destination.ip" } } }
        ]
      },
      "aggs": {
        "by_time": {
          "date_histogram": { "field": "@timestamp", "fixed_interval": "5m" }
        }
      }
    }
  }
}`,
    kql: `CommonSecurityLog
| where TimeGenerated > ago(6h)
| summarize ConnectionCount = count() by SourceIP, DestinationIP, DestinationPort, bin(TimeGenerated, 5m)
| summarize AvgCount = avg(ConnectionCount), StdDev = stdev(ConnectionCount), Intervals = count() by SourceIP, DestinationIP, DestinationPort
| extend Jitter = StdDev / AvgCount
| where Jitter < 0.15 and Intervals > 12
| sort by Jitter asc`,
  },
]

const CATEGORIES = ['All', ...Array.from(new Set(TEMPLATES.map(t => t.category)))]

export default function SIEMQueryBuilder() {
  const [platform, setPlatform] = useState<'splunk' | 'elastic' | 'kql'>('splunk')
  const [category, setCategory] = useState('All')
  const [selected, setSelected] = useState<QueryTemplate>(TEMPLATES[0])
  const [customQuery, setCustomQuery] = useState('')
  const [copied, setCopied] = useState('')
  const [showCustom, setShowCustom] = useState(false)

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const filtered = TEMPLATES.filter(t => category === 'All' || t.category === category)

  const platformLabels = {
    splunk: { name: 'Splunk SPL', color: '#ff6b35' },
    elastic: { name: 'Elastic DSL', color: '#ffd700' },
    kql: { name: 'KQL (Azure Sentinel)', color: '#00d4ff' },
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">SIEM Query Builder</h2>
        <p className="section-subheading">Ready-to-use detection queries for Splunk, Elasticsearch, and Azure Sentinel (KQL)</p>
      </div>

      {/* Platform selector */}
      <div className="card">
        <div className="card-header"><span className="card-title">Target Platform</span></div>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(platformLabels) as Array<keyof typeof platformLabels>).map(p => (
            <button
              key={p}
              onClick={() => setPlatform(p)}
              className={`tab-btn ${platform === p ? 'active' : ''}`}
              style={platform === p ? { color: platformLabels[p].color, borderColor: platformLabels[p].color } : {}}
            >
              {platformLabels[p].name}
            </button>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        {/* Template list */}
        <div className="space-y-3">
          <div className="card">
            <div className="card-header"><span className="card-title">Query Templates</span></div>
            <div className="flex flex-wrap gap-1 mb-3">
              {CATEGORIES.map(c => (
                <button key={c} onClick={() => setCategory(c)} className={`tab-btn text-xs ${category === c ? 'active' : ''}`}>{c}</button>
              ))}
            </div>
            <div className="space-y-1">
              {filtered.map(t => (
                <button
                  key={t.id}
                  onClick={() => setSelected(t)}
                  className={`w-full text-left p-2 rounded transition-all ${selected.id === t.id ? 'border-glow-blue' : ''}`}
                  style={{ background: 'rgba(10,20,40,0.6)', border: `1px solid ${selected.id === t.id ? 'rgba(0,212,255,0.4)' : 'rgba(0,212,255,0.08)'}` }}
                >
                  <div className="text-xs font-medium text-gray-200">{t.name}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{t.category}</div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Query panel */}
        <div className="md:col-span-2 space-y-4">
          <div className="card">
            <div className="flex items-start justify-between flex-wrap gap-2 mb-3">
              <div>
                <div className="text-sm font-semibold text-gray-200">{selected.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">{selected.description}</div>
              </div>
              <div className="flex gap-2">
                <span className="badge badge-info">{selected.category}</span>
                <button
                  onClick={() => copy(selected[platform], `query-${selected.id}`)}
                  className="btn-primary text-xs py-1"
                >
                  {copied === `query-${selected.id}` ? '✓ Copied!' : 'Copy Query'}
                </button>
              </div>
            </div>
            <div className="text-xs text-gray-500 mb-2" style={{ color: platformLabels[platform].color }}>
              ● {platformLabels[platform].name}
            </div>
            <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{selected[platform]}</pre>
          </div>

          {/* All platforms side by side */}
          <div className="card">
            <div className="card-header"><span className="card-title">All Platform Variants</span></div>
            <div className="space-y-4">
              {(Object.keys(platformLabels) as Array<keyof typeof platformLabels>).map(p => (
                <div key={p}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold" style={{ color: platformLabels[p].color }}>{platformLabels[p].name}</span>
                    <button onClick={() => copy(selected[p], `all-${p}`)} className="text-xs text-blue-400 hover:underline">
                      {copied === `all-${p}` ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{selected[p]}</pre>
                </div>
              ))}
            </div>
          </div>

          {/* Custom query builder */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Custom Query Notepad</span>
              <button onClick={() => setShowCustom(!showCustom)} className="ml-auto text-xs text-blue-400">{showCustom ? 'Hide' : 'Show'}</button>
            </div>
            {showCustom && (
              <div>
                <textarea
                  className="cyber-textarea w-full h-40 font-mono text-xs"
                  value={customQuery}
                  onChange={e => setCustomQuery(e.target.value)}
                  placeholder={`Write your custom ${platformLabels[platform].name} query here...`}
                />
                <div className="flex gap-2 mt-2">
                  <button onClick={() => copy(customQuery, 'custom')} disabled={!customQuery.trim()} className="btn-primary text-xs disabled:opacity-50">
                    {copied === 'custom' ? '✓ Copied' : 'Copy Query'}
                  </button>
                  <button onClick={() => setCustomQuery('')} className="btn-danger text-xs">Clear</button>
                </div>
              </div>
            )}
          </div>

          {/* Query tuning tips */}
          <div className="card">
            <div className="card-header"><span className="card-title">Query Tuning Tips</span></div>
            <div className="space-y-2 text-xs text-gray-400">
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Adjust time ranges to balance coverage vs. performance (start with 1h, expand if needed)</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Add your environment&apos;s known-good IPs to exclusion lists to reduce false positives</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Tune threshold values (count &gt; N) based on your baseline traffic</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Test queries in development before applying to production alerts</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Document all custom queries with description, author, and date</span></div>
              <div className="flex gap-2"><span className="text-blue-400">›</span><span>Map queries to MITRE ATT&amp;CK techniques for better coverage visibility</span></div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
