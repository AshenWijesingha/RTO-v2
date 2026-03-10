'use client'

import React, { useState, useCallback } from 'react'
import { copyToClipboard, defang, lsGet, lsSet, detectIOCType } from '@/lib/utils'

interface ApiKeys {
  abuseipdb: string
  virustotal: string
  shodan: string
  otx: string
}

interface ResultSection {
  title: string
  data: Record<string, string | number | boolean | null>
}

export default function ThreatIntelligence() {
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<ResultSection[]>([])
  const [error, setError] = useState('')
  const [apiKeys] = useState<ApiKeys>(() => lsGet<ApiKeys>('bt_apikeys', { abuseipdb: '', virustotal: '', shodan: '', otx: '' }))
  const [activeTab, setActiveTab] = useState<'ip' | 'domain' | 'hash' | 'url'>('ip')
  const [copied, setCopied] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const analyze = useCallback(async () => {
    const t = target.trim()
    if (!t) return
    setLoading(true)
    setError('')
    setResults([])

    const sections: ResultSection[] = []

    try {
      // ── IP Geo / ASN (ip-api.com – free, CORS-enabled) ──
      if (activeTab === 'ip') {
        try {
          const res = await fetch(`https://ip-api.com/json/${encodeURIComponent(t)}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query`)
          if (res.ok) {
            const d = await res.json()
            if (d.status === 'success') {
              sections.push({
                title: '🌍 Geolocation & ASN (ip-api.com)',
                data: {
                  IP: d.query,
                  Country: `${d.country} (${d.countryCode})`,
                  Region: d.regionName,
                  City: d.city,
                  ISP: d.isp,
                  Organization: d.org,
                  ASN: d.as,
                  'ASN Name': d.asname,
                  'Reverse DNS': d.reverse || 'N/A',
                  Timezone: d.timezone,
                  'Lat/Lon': `${d.lat}, ${d.lon}`,
                  'Is Mobile': d.mobile ? 'Yes' : 'No',
                  'Is Proxy/VPN': d.proxy ? '⚠ YES' : 'No',
                  'Is Hosting': d.hosting ? 'Yes' : 'No',
                }
              })
            }
          }
        } catch {}

        // ── AbuseIPDB (requires API key) ──
        if (apiKeys.abuseipdb) {
          try {
            const res = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(t)}&maxAgeInDays=90&verbose=true`, {
              headers: { Key: apiKeys.abuseipdb, Accept: 'application/json' }
            })
            if (res.ok) {
              const d = await res.json()
              const data = d.data
              sections.push({
                title: '🚨 AbuseIPDB Reputation',
                data: {
                  'IP Address': data.ipAddress,
                  'Abuse Confidence Score': `${data.abuseConfidenceScore}%`,
                  'Total Reports': data.totalReports,
                  'Distinct Users Reported': data.numDistinctUsers,
                  'Last Reported': data.lastReportedAt || 'Never',
                  'Is Public': data.isPublic ? 'Yes' : 'No',
                  'Is Whitelisted': data.isWhitelisted ? 'Yes' : 'No',
                  'Usage Type': data.usageType || 'Unknown',
                  'ISP': data.isp,
                  'Domain': data.domain || 'N/A',
                  'Country': data.countryCode,
                  'Risk Level': data.abuseConfidenceScore >= 80 ? '🔴 HIGH RISK' : data.abuseConfidenceScore >= 30 ? '🟡 MEDIUM RISK' : '🟢 LOW RISK',
                }
              })
            }
          } catch {}
        } else {
          sections.push({
            title: '🚨 AbuseIPDB Reputation',
            data: { Status: 'API key required. Add your AbuseIPDB key in Settings.', 'Get Free Key': 'https://www.abuseipdb.com/api' }
          })
        }

        // ── Shodan (requires API key) ──
        if (apiKeys.shodan) {
          try {
            const res = await fetch(`https://api.shodan.io/shodan/host/${encodeURIComponent(t)}?key=${apiKeys.shodan}`)
            if (res.ok) {
              const d = await res.json()
              sections.push({
                title: '🔭 Shodan Host Intelligence',
                data: {
                  'IP': d.ip_str,
                  'Organization': d.org || 'N/A',
                  'ISP': d.isp || 'N/A',
                  'ASN': d.asn || 'N/A',
                  'Country': d.country_name || 'N/A',
                  'City': d.city || 'N/A',
                  'Open Ports': (d.ports || []).join(', ') || 'None found',
                  'Hostnames': (d.hostnames || []).join(', ') || 'None',
                  'Domains': (d.domains || []).join(', ') || 'None',
                  'OS': d.os || 'Unknown',
                  'Last Update': d.last_update || 'N/A',
                  'Total Services': d.data?.length || 0,
                  'Vulnerabilities': d.vulns ? Object.keys(d.vulns).join(', ') : 'None detected',
                }
              })
            }
          } catch {}
        }
      }

      // ── Domain analysis ──
      if (activeTab === 'domain') {
        // WHOIS via whois.domaintools.com / rdap
        try {
          const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(t)}`)
          if (res.ok) {
            const d = await res.json()
            const ns = d.nameservers?.map((n: { ldhName: string }) => n.ldhName).join(', ') || 'N/A'
            const status = d.status?.join(', ') || 'N/A'
            const events = d.events || []
            const registered = events.find((e: { eventAction: string }) => e.eventAction === 'registration')?.eventDate || 'N/A'
            const updated = events.find((e: { eventAction: string }) => e.eventAction === 'last changed')?.eventDate || 'N/A'
            const expires = events.find((e: { eventAction: string }) => e.eventAction === 'expiration')?.eventDate || 'N/A'
            sections.push({
              title: '🌐 Domain RDAP / WHOIS',
              data: {
                Domain: d.ldhName || t,
                Registered: registered,
                'Last Updated': updated,
                Expires: expires,
                'Name Servers': ns,
                Status: status,
                'Registry': d.port43 || 'N/A',
              }
            })
          }
        } catch {}

        // DNS records
        try {
          const types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME']
          const dnsResults: Record<string, string> = {}
          await Promise.all(types.map(async type => {
            try {
              const r = await fetch(`https://dns.google/resolve?name=${encodeURIComponent(t)}&type=${type}`)
              if (r.ok) {
                const data = await r.json()
                if (data.Answer?.length) {
                  dnsResults[type] = data.Answer.map((a: { data: string }) => a.data).join(' | ')
                }
              }
            } catch {}
          }))
          if (Object.keys(dnsResults).length) {
            sections.push({ title: '📡 DNS Records (Google DNS)', data: dnsResults })
          }
        } catch {}
      }

      // ── Hash lookup ──
      if (activeTab === 'hash') {
        // MalwareBazaar (free, no key needed)
        try {
          const res = await fetch('https://mb-api.abuse.ch/api/v1/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `query=get_info&hash=${encodeURIComponent(t)}`
          })
          if (res.ok) {
            const d = await res.json()
            if (d.query_status === 'hash_not_found') {
              sections.push({ title: '🦠 MalwareBazaar', data: { Status: '✅ Not found in MalwareBazaar database', Hash: t } })
            } else if (d.data?.length) {
              const item = d.data[0]
              sections.push({
                title: '🦠 MalwareBazaar Result',
                data: {
                  'Status': '🔴 MALICIOUS - Found in MalwareBazaar',
                  'File Name': item.file_name || 'N/A',
                  'File Type': item.file_type_mime || 'N/A',
                  'File Size': item.file_size ? `${item.file_size} bytes` : 'N/A',
                  'First Seen': item.first_seen || 'N/A',
                  'Last Seen': item.last_seen || 'N/A',
                  'Tags': item.tags?.join(', ') || 'None',
                  'Signature': item.signature || 'N/A',
                  'Reporter': item.reporter || 'N/A',
                  'MD5': item.md5_hash || 'N/A',
                  'SHA1': item.sha1_hash || 'N/A',
                  'SHA256': item.sha256_hash || 'N/A',
                }
              })
            }
          }
        } catch {}

        // VirusTotal hash lookup
        if (apiKeys.virustotal) {
          try {
            const res = await fetch(`https://www.virustotal.com/api/v3/files/${encodeURIComponent(t)}`, {
              headers: { 'x-apikey': apiKeys.virustotal }
            })
            if (res.ok) {
              const d = await res.json()
              const attr = d.data?.attributes
              const stats = attr?.last_analysis_stats
              sections.push({
                title: '🦠 VirusTotal File Analysis',
                data: {
                  'MD5': attr?.md5 || 'N/A',
                  'SHA1': attr?.sha1 || 'N/A',
                  'SHA256': attr?.sha256 || 'N/A',
                  'File Type': attr?.type_description || 'N/A',
                  'File Size': attr?.size ? `${attr.size} bytes` : 'N/A',
                  'Malicious': `${stats?.malicious || 0} engines`,
                  'Suspicious': `${stats?.suspicious || 0} engines`,
                  'Clean': `${stats?.undetected || 0} engines`,
                  'Verdict': stats?.malicious > 0 ? `🔴 MALICIOUS (${stats.malicious}/${(stats.malicious + stats.suspicious + stats.undetected)} engines)` : '🟢 CLEAN',
                  'First Submission': attr?.first_submission_date ? new Date(attr.first_submission_date * 1000).toLocaleString() : 'N/A',
                  'Names': attr?.names?.slice(0, 5).join(', ') || 'N/A',
                }
              })
            }
          } catch {}
        }
      }

      // ── URL analysis ──
      if (activeTab === 'url') {
        if (apiKeys.virustotal) {
          try {
            const encoded = btoa(t).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
            const res = await fetch(`https://www.virustotal.com/api/v3/urls/${encoded}`, {
              headers: { 'x-apikey': apiKeys.virustotal }
            })
            if (res.ok) {
              const d = await res.json()
              const attr = d.data?.attributes
              const stats = attr?.last_analysis_stats
              sections.push({
                title: '🔗 VirusTotal URL Analysis',
                data: {
                  URL: attr?.url || t,
                  'Final URL': attr?.last_final_url || 'N/A',
                  'Title': attr?.title || 'N/A',
                  'Malicious': `${stats?.malicious || 0} engines`,
                  'Suspicious': `${stats?.suspicious || 0} engines`,
                  'Clean': `${stats?.harmless || 0} engines`,
                  'Verdict': stats?.malicious > 0 ? `🔴 MALICIOUS (${stats.malicious} engines)` : '🟢 CLEAN',
                  'Categories': Object.values(attr?.categories || {}).slice(0, 3).join(', ') || 'N/A',
                  'Last Analysis': attr?.last_analysis_date ? new Date(attr.last_analysis_date * 1000).toLocaleString() : 'N/A',
                }
              })
            }
          } catch {}
        } else {
          sections.push({
            title: '🔗 URL Analysis',
            data: { Status: 'VirusTotal API key required for URL analysis. Add key in Settings.' }
          })
        }

        // URLhaus lookup
        try {
          const res = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `url=${encodeURIComponent(t)}`
          })
          if (res.ok) {
            const d = await res.json()
            if (d.query_status === 'no_results') {
              sections.push({ title: '🔗 URLhaus', data: { Status: '✅ Not found in URLhaus database' } })
            } else if (d.id) {
              sections.push({
                title: '🔗 URLhaus Result',
                data: {
                  'Status': `🔴 MALICIOUS - ${d.threat || 'Malware'}`,
                  'URL Status': d.url_status,
                  'Date Added': d.date_added,
                  'Threat': d.threat || 'N/A',
                  'Tags': d.tags?.join(', ') || 'None',
                  'Reporter': d.reporter || 'N/A',
                }
              })
            }
          }
        } catch {}
      }

      if (sections.length === 0) {
        setError('No results returned. Check your input and API keys in Settings.')
      } else {
        setResults(sections)
      }
    } catch (e) {
      setError(`Analysis failed: ${e instanceof Error ? e.message : 'Unknown error'}`)
    } finally {
      setLoading(false)
    }
  }, [target, activeTab, apiKeys])

  const tabs = [
    { id: 'ip' as const, label: 'IP Address', placeholder: '8.8.8.8' },
    { id: 'domain' as const, label: 'Domain', placeholder: 'example.com' },
    { id: 'hash' as const, label: 'File Hash', placeholder: 'MD5 / SHA1 / SHA256' },
    { id: 'url' as const, label: 'URL', placeholder: 'https://example.com/path' },
  ]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Threat Intelligence</h2>
        <p className="section-subheading">Analyze IPs, domains, file hashes, and URLs against threat intelligence sources</p>
      </div>

      <div className="card">
        {/* Tabs */}
        <div className="flex flex-wrap gap-2 mb-4">
          {tabs.map(tab => (
            <button key={tab.id} onClick={() => { setActiveTab(tab.id); setResults([]); setError('') }} className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}>
              {tab.label}
            </button>
          ))}
        </div>

        {/* Input */}
        <div className="flex gap-2 flex-wrap">
          <input
            className="cyber-input flex-1 min-w-0"
            value={target}
            onChange={e => setTarget(e.target.value)}
            placeholder={tabs.find(t => t.id === activeTab)?.placeholder}
            onKeyDown={e => e.key === 'Enter' && analyze()}
          />
          <button onClick={analyze} disabled={loading || !target.trim()} className="btn-primary flex items-center gap-2 whitespace-nowrap disabled:opacity-50">
            {loading ? <span className="spinner" /> : '🔍'}
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>
          {target && (
            <button onClick={() => copy(defang(target), 'defang')} className="btn-primary whitespace-nowrap">
              {copied === 'defang' ? '✓ Copied' : 'Defang & Copy'}
            </button>
          )}
        </div>

        {/* Detected type */}
        {target && (
          <div className="mt-2 text-xs text-gray-500">
            Detected: <span className="text-blue-400">{detectIOCType(target)}</span>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="alert-warning">
          <span>⚠</span>
          <span className="text-sm text-yellow-200">{error}</span>
        </div>
      )}

      {/* Results */}
      {results.length > 0 && results.map((section, idx) => (
        <div key={idx} className="card">
          <div className="card-header">
            <span className="card-title">{section.title}</span>
            <button
              onClick={() => copy(JSON.stringify(section.data, null, 2), `section-${idx}`)}
              className="ml-auto text-xs text-blue-400 hover:underline"
            >
              {copied === `section-${idx}` ? '✓ Copied' : 'Copy JSON'}
            </button>
          </div>
          <div className="space-y-1">
            {Object.entries(section.data).map(([key, val]) => (
              <div key={key} className="flex items-start gap-2 py-1 border-b" style={{ borderColor: 'rgba(0,212,255,0.06)' }}>
                <span className="text-xs text-gray-500 w-40 shrink-0">{key}</span>
                <span className="text-xs font-mono text-gray-200 break-all">{String(val ?? 'N/A')}</span>
              </div>
            ))}
          </div>
        </div>
      ))}

      {/* Info box */}
      <div className="alert-info">
        <span>ℹ</span>
        <div className="text-xs text-blue-200">
          <strong>Data Sources:</strong> ip-api.com (free, no key), AbuseIPDB (API key required), Shodan (API key required),
          VirusTotal (API key required), MalwareBazaar (free), URLhaus (free), RDAP (free).
          Add your API keys in the <button onClick={() => {}} className="underline">Settings</button> section for full functionality.
        </div>
      </div>
    </div>
  )
}
