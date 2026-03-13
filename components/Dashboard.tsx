'use client'

import React, { useState, useEffect } from 'react'
import { lsGet, formatDate } from '@/lib/utils'

interface IOC { id: string; value: string; type: string; severity: string; timestamp: string }
interface Incident { id: string; title: string; severity: string; status: string; timestamp: string }

export default function Dashboard({ onNavigate }: { onNavigate: (s: string) => void }) {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [now, setNow] = useState('')

  useEffect(() => {
    setIocs(lsGet<IOC[]>('bt_iocs', []))
    setIncidents(lsGet<Incident[]>('bt_incidents', []))
    const tick = () => setNow(new Date().toLocaleString())
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  const criticalIOCs = iocs.filter(i => i.severity === 'Critical').length
  const highIOCs = iocs.filter(i => i.severity === 'High').length
  const activeIncidents = incidents.filter(i => i.status !== 'Resolved' && i.status !== 'Closed').length
  const openIncidents = incidents.filter(i => i.status === 'Open').length

  const quickActions = [
    { label: 'Analyze IP/Domain', icon: '🔍', section: 'threat-intel', color: '#ff4444' },
    { label: 'Add IOC', icon: '📌', section: 'ioc-manager', color: '#ff6b35' },
    { label: 'New Incident', icon: '🚨', section: 'incident-response', color: '#ffd700' },
    { label: 'Threat Hunt', icon: '🎯', section: 'threat-hunting', color: '#00ffcc' },
    { label: 'Build SIEM Query', icon: '⚡', section: 'siem-queries', color: '#00d4ff' },
    { label: 'Build Nmap Scan', icon: '🔭', section: 'nmap-builder', color: '#39ff14' },
    { label: 'CVE Lookup', icon: '🛡', section: 'vulnerability', color: '#ff6b35' },
  ]

  const resources = [
    { name: 'MITRE ATT&CK', url: 'https://attack.mitre.org', desc: 'Adversary tactics & techniques' },
    { name: 'NIST NVD', url: 'https://nvd.nist.gov', desc: 'National Vulnerability Database' },
    { name: 'CVE Details', url: 'https://www.cvedetails.com', desc: 'CVE security vulnerability database' },
    { name: 'AbuseIPDB', url: 'https://www.abuseipdb.com', desc: 'IP abuse reports & reputation' },
    { name: 'VirusTotal', url: 'https://www.virustotal.com', desc: 'File, URL, IP & domain analysis' },
    { name: 'Shodan', url: 'https://www.shodan.io', desc: 'Internet-connected device search' },
    { name: 'AlienVault OTX', url: 'https://otx.alienvault.com', desc: 'Open threat intelligence' },
    { name: 'Threat Fox', url: 'https://threatfox.abuse.ch', desc: 'IOC sharing platform' },
    { name: 'MalwareBazaar', url: 'https://bazaar.abuse.ch', desc: 'Malware sample database' },
    { name: 'URLhaus', url: 'https://urlhaus.abuse.ch', desc: 'Malicious URL database' },
    { name: 'CIRCL MISP', url: 'https://www.misp-project.org', desc: 'Threat intelligence sharing' },
    { name: 'Any.run', url: 'https://app.any.run', desc: 'Interactive malware analysis' },
  ]

  const recentIOCs = [...iocs].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 5)
  const recentIncidents = [...incidents].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 3)

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h1 className="section-heading text-2xl">Blue Team Cyber Dashboard</h1>
          <p className="section-subheading text-sm">Threat Analysis, Detection & Incident Response Platform</p>
        </div>
        <div className="text-xs font-mono text-blue-400/70 text-right">
          <div className="flex items-center gap-2 justify-end">
            <span className="pulse-dot"></span>
            <span>SYSTEM ACTIVE</span>
          </div>
          <div className="mt-1 text-gray-500">{now}</div>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard label="Total IOCs" value={iocs.length} color="#00d4ff" icon="📌" />
        <StatCard label="Critical IOCs" value={criticalIOCs} color="#ff4444" icon="🚨" />
        <StatCard label="Active Incidents" value={activeIncidents} color="#ffd700" icon="⚠" />
        <StatCard label="Open Incidents" value={openIncidents} color="#ff6b35" icon="🔥" />
      </div>

      {/* IOC Severity Breakdown */}
      <div className="grid md:grid-cols-2 gap-4">
        <div className="card">
          <div className="card-header">
            <span className="text-sm">📊</span>
            <span className="card-title">IOC Severity Breakdown</span>
          </div>
          <div className="space-y-3">
            {(['Critical', 'High', 'Medium', 'Low', 'Info'] as const).map(sev => {
              const count = iocs.filter(i => i.severity === sev).length
              const pct = iocs.length ? Math.round((count / iocs.length) * 100) : 0
              const colors: Record<string, string> = {
                Critical: '#ff4444', High: '#ff6b35', Medium: '#ffd700', Low: '#00d4ff', Info: '#00ffcc'
              }
              return (
                <div key={sev}>
                  <div className="flex justify-between text-xs mb-1">
                    <span style={{ color: colors[sev] }}>{sev}</span>
                    <span className="text-gray-500">{count} ({pct}%)</span>
                  </div>
                  <div className="progress-bar h-1.5">
                    <div
                      className="progress-fill"
                      style={{ width: `${pct}%`, background: colors[sev] }}
                    />
                  </div>
                </div>
              )
            })}
            {iocs.length === 0 && (
              <div className="text-center text-xs text-gray-500 py-4">
                No IOCs tracked yet. <button onClick={() => onNavigate('ioc-manager')} className="text-blue-400 hover:underline">Add IOCs →</button>
              </div>
            )}
          </div>
        </div>

        {/* Quick Actions */}
        <div className="card">
          <div className="card-header">
            <span className="text-sm">⚡</span>
            <span className="card-title">Quick Actions</span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {quickActions.map(a => (
              <button
                key={a.section}
                onClick={() => onNavigate(a.section)}
                className="flex items-center gap-2 p-2.5 rounded-lg text-xs font-medium transition-all hover:scale-[1.02]"
                style={{
                  background: `rgba(${hexToRgb(a.color)}, 0.08)`,
                  border: `1px solid rgba(${hexToRgb(a.color)}, 0.2)`,
                  color: a.color,
                }}
              >
                <span>{a.icon}</span>
                <span>{a.label}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Activity */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Recent IOCs */}
        <div className="card">
          <div className="card-header">
            <span>📌</span>
            <span className="card-title">Recent IOCs</span>
            <button onClick={() => onNavigate('ioc-manager')} className="ml-auto text-xs text-blue-400 hover:underline">View all →</button>
          </div>
          {recentIOCs.length === 0 ? (
            <div className="text-center text-xs text-gray-500 py-6">No IOCs tracked yet</div>
          ) : (
            <div className="space-y-2">
              {recentIOCs.map(ioc => (
                <div key={ioc.id} className="flex items-center gap-2 p-2 rounded" style={{ background: 'rgba(0,212,255,0.03)' }}>
                  <span className={`badge badge-${ioc.severity.toLowerCase()}`}>{ioc.severity}</span>
                  <span className="font-mono text-xs text-gray-300 truncate flex-1">{ioc.value}</span>
                  <span className="text-xs text-gray-600 whitespace-nowrap">{ioc.type}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Recent Incidents */}
        <div className="card">
          <div className="card-header">
            <span>🚨</span>
            <span className="card-title">Recent Incidents</span>
            <button onClick={() => onNavigate('incident-response')} className="ml-auto text-xs text-blue-400 hover:underline">View all →</button>
          </div>
          {recentIncidents.length === 0 ? (
            <div className="text-center text-xs text-gray-500 py-6">No incidents tracked yet</div>
          ) : (
            <div className="space-y-2">
              {recentIncidents.map(inc => (
                <div key={inc.id} className="p-2 rounded" style={{ background: 'rgba(0,212,255,0.03)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`badge badge-${inc.severity.toLowerCase()}`}>{inc.severity}</span>
                    <span className="text-xs font-medium text-gray-300 truncate">{inc.title}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-gray-600">{inc.status}</span>
                    <span className="text-xs text-gray-600">·</span>
                    <span className="text-xs text-gray-600">{formatDate(inc.timestamp)}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* External Resources */}
      <div className="card">
        <div className="card-header">
          <span>🌐</span>
          <span className="card-title">Threat Intelligence Resources</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
          {resources.map(r => (
            <a
              key={r.name}
              href={r.url}
              target="_blank"
              rel="noopener noreferrer"
              className="glass-hover p-3 rounded-lg flex flex-col gap-1"
              style={{ border: '1px solid rgba(0,212,255,0.08)' }}
            >
              <div className="text-xs font-semibold text-blue-400">{r.name}</div>
              <div className="text-xs text-gray-500">{r.desc}</div>
            </a>
          ))}
        </div>
      </div>

      {/* Blue Team Workflow */}
      <div className="card">
        <div className="card-header">
          <span>📘</span>
          <span className="card-title">NIST Incident Response Lifecycle</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { phase: '1. Preparation', color: '#00d4ff', items: ['Asset inventory', 'Security policies', 'IR plan & runbooks', 'Team training', 'Security tools setup', 'Threat intel feeds'] },
            { phase: '2. Detection & Analysis', color: '#ffd700', items: ['Monitor SIEM alerts', 'Analyze logs', 'Identify IOCs', 'Assess scope & impact', 'Threat hunt', 'Collect evidence'] },
            { phase: '3. Containment & Eradication', color: '#ff6b35', items: ['Isolate affected systems', 'Block malicious IOCs', 'Apply emergency patches', 'Reset credentials', 'Remove malware', 'Rebuild if needed'] },
            { phase: '4. Recovery & Lessons Learned', color: '#39ff14', items: ['Restore from backups', 'Monitor for re-infection', 'Validate recovery', 'Post-incident review', 'Update playbooks', 'Report to stakeholders'] },
          ].map(p => (
            <div key={p.phase} className="rounded-lg p-3" style={{ background: 'rgba(10,20,40,0.6)', borderLeft: `3px solid ${p.color}` }}>
              <div className="text-xs font-semibold mb-2" style={{ color: p.color }}>{p.phase}</div>
              <ul className="space-y-1">
                {p.items.map(item => (
                  <li key={item} className="text-xs text-gray-400 flex items-start gap-1">
                    <span style={{ color: p.color }}>›</span> {item}
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, color, icon }: { label: string; value: number; color: string; icon: string }) {
  return (
    <div className="stat-card" style={{ borderColor: `rgba(${hexToRgb(color)}, 0.2)` }}>
      <div className="flex items-center gap-2">
        <span>{icon}</span>
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className="text-3xl font-bold mt-1" style={{ color }}>{value}</div>
    </div>
  )
}

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return `${r},${g},${b}`
}
