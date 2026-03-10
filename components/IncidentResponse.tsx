'use client'

import React, { useState, useEffect } from 'react'
import { lsGet, lsSet, now, formatDate, downloadJSON, downloadText, toCSV } from '@/lib/utils'

interface TimelineEvent {
  id: string
  timestamp: string
  description: string
  analyst: string
  action: string
}

export interface Incident {
  id: string
  title: string
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  status: 'Open' | 'In Progress' | 'Contained' | 'Eradicated' | 'Resolved' | 'Closed'
  assignee: string
  description: string
  affectedSystems: string
  iocs: string
  timeline: TimelineEvent[]
  timestamp: string
  closedAt: string
}

const INCIDENT_TYPES = [
  'Ransomware', 'Phishing', 'Data Breach', 'DDoS', 'Malware Infection',
  'Unauthorized Access', 'Insider Threat', 'Supply Chain Attack', 'BEC / Email Fraud',
  'Credential Theft', 'Web Application Attack', 'Network Intrusion', 'Other'
]

const PLAYBOOKS: Record<string, { phase: string; steps: string[] }[]> = {
  Ransomware: [
    { phase: '🔴 Detection', steps: ['Identify encrypted files and ransom note', 'Check for lateral movement indicators', 'Review recent logins and process execution', 'Identify patient zero (initial infection vector)', 'Check backup integrity immediately'] },
    { phase: '🟡 Containment', steps: ['Immediately isolate affected systems from network', 'Disable compromised accounts', 'Block C2 domains/IPs at firewall/proxy', 'Preserve forensic evidence (memory dump, disk image)', 'Alert legal, HR, and executive leadership'] },
    { phase: '🟠 Eradication', steps: ['Identify and remove malware artifacts', 'Scan all systems for additional infections', 'Reset all potentially compromised credentials', 'Patch exploited vulnerabilities', 'Review and harden Active Directory'] },
    { phase: '🟢 Recovery', steps: ['Restore from clean backups (verify integrity first)', 'Rebuild affected systems from known-good images', 'Monitor restored systems closely', 'Implement additional endpoint controls', 'Validate business operations resumption'] },
    { phase: '📋 Post-Incident', steps: ['Conduct root cause analysis', 'Document timeline and actions taken', 'Update IR playbook based on lessons learned', 'Brief leadership with executive summary', 'Consider reporting to CISA/FBI if applicable'] },
  ],
  Phishing: [
    { phase: '🔴 Detection', steps: ['Identify phishing email and affected recipients', 'Check if credentials were submitted', 'Review email gateway logs', 'Identify click-through URL and any downloads', 'Check for other recipients of same campaign'] },
    { phase: '🟡 Containment', steps: ['Remove phishing email from all mailboxes', 'Block sender domain/IP at email gateway', 'Reset passwords for users who clicked/submitted credentials', 'Enable MFA for affected accounts immediately', 'Block phishing URL at web proxy'] },
    { phase: '🟠 Eradication', steps: ['Check for OAuth app consent grants', 'Review mailbox forwarding rules for tampering', 'Search for malware dropped via phishing', 'Audit recently created accounts and rules', 'Review audit logs for data access post-compromise'] },
    { phase: '🟢 Recovery', steps: ['Re-enable accounts after password reset and MFA enforcement', 'Restore any deleted emails or data', 'Deploy additional email security controls', 'Review email filtering rules', 'Send security awareness notification to users'] },
    { phase: '📋 Post-Incident', steps: ['Report phishing campaign to anti-phishing authorities', 'Update email security filters', 'Conduct targeted security awareness training', 'Document IOCs for future detection', 'Review DMARC/DKIM/SPF configuration'] },
  ],
  'Data Breach': [
    { phase: '🔴 Detection', steps: ['Determine scope of exposed data (type, volume, sensitivity)', 'Identify affected data subjects', 'Preserve evidence of exfiltration', 'Identify exfiltration method and timeline', 'Engage legal counsel immediately'] },
    { phase: '🟡 Containment', steps: ['Revoke access for compromised accounts/credentials', 'Disable exposed APIs or services', 'Block exfiltration destinations at network level', 'Preserve all relevant logs', 'Begin regulatory notification assessment'] },
    { phase: '🟠 Eradication', steps: ['Close the vulnerability that allowed breach', 'Scan for additional compromised data', 'Review and minimize data access permissions', 'Check for persistent attacker access', 'Validate all access controls'] },
    { phase: '🟢 Recovery', steps: ['Restore secure operations', 'Notify affected individuals per legal requirements', 'Engage credit monitoring services if needed', 'File regulatory notifications (GDPR 72hr, HIPAA 60 days, etc.)', 'Monitor for downstream fraud/misuse'] },
    { phase: '📋 Post-Incident', steps: ['Conduct privacy impact assessment', 'Update data classification and DLP policies', 'Implement additional monitoring', 'Brief board and leadership', 'Update incident response procedures'] },
  ],
  DDoS: [
    { phase: '🔴 Detection', steps: ['Confirm DDoS attack vs. traffic spike', 'Identify attack type (volumetric, protocol, application layer)', 'Assess business impact and affected services', 'Contact upstream ISP/CDN provider', 'Activate DDoS protection service'] },
    { phase: '🟡 Containment', steps: ['Enable rate limiting and traffic scrubbing', 'Implement geo-blocking if traffic sourced from specific regions', 'Work with CDN/ISP for upstream filtering', 'Prioritize critical service traffic', 'Consider traffic blackholing if necessary'] },
    { phase: '🟠 Eradication', steps: ['Identify and block botnet C2 infrastructure', 'Submit abuse reports to upstream providers', 'Work with ISP for BGP blackhole routing', 'Apply application-layer WAF rules', 'Tune rate limiting thresholds'] },
    { phase: '🟢 Recovery', steps: ['Gradually restore services', 'Monitor for attack resumption', 'Test service restoration and performance', 'Review and update DDoS response playbook', 'Implement long-term DDoS mitigation'] },
    { phase: '📋 Post-Incident', steps: ['Document attack timeline and traffic volumes', 'Evaluate DDoS protection solution effectiveness', 'Assess need for additional bandwidth or CDN', 'Review business continuity procedures', 'Update runbooks and contact lists'] },
  ],
}

const SEV_COLORS: Record<string, string> = { Critical: '#ff4444', High: '#ff6b35', Medium: '#ffd700', Low: '#00d4ff' }
const STATUS_COLORS: Record<string, string> = {
  Open: '#ff4444', 'In Progress': '#ffd700', Contained: '#ff6b35',
  Eradicated: '#00ffcc', Resolved: '#39ff14', Closed: '#6b7280'
}

export default function IncidentResponse() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [selected, setSelected] = useState<string | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [playbook, setPlaybook] = useState('')
  const [form, setForm] = useState<Partial<Incident>>({})
  const [timelineEntry, setTimelineEntry] = useState({ description: '', analyst: '', action: '' })
  const [activeTab, setActiveTab] = useState<'details' | 'timeline' | 'playbook'>('details')

  useEffect(() => { setIncidents(lsGet<Incident[]>('bt_incidents', [])) }, [])

  const persist = (updated: Incident[]) => { setIncidents(updated); lsSet('bt_incidents', updated) }

  const openNew = () => {
    setForm({ title: '', type: INCIDENT_TYPES[0], severity: 'High', status: 'Open', assignee: '', description: '', affectedSystems: '', iocs: '' })
    setShowForm(true)
    setSelected(null)
  }

  const submitForm = () => {
    if (!form.title?.trim()) return
    if (selected) {
      persist(incidents.map(i => i.id === selected ? { ...i, ...form } as Incident : i))
    } else {
      const inc: Incident = {
        id: crypto.randomUUID(),
        title: form.title!,
        type: form.type || INCIDENT_TYPES[0],
        severity: form.severity as Incident['severity'] || 'High',
        status: 'Open',
        assignee: form.assignee || '',
        description: form.description || '',
        affectedSystems: form.affectedSystems || '',
        iocs: form.iocs || '',
        timeline: [{ id: crypto.randomUUID(), timestamp: now(), description: 'Incident created', analyst: form.assignee || 'System', action: 'Create' }],
        timestamp: now(),
        closedAt: '',
      }
      persist([inc, ...incidents])
      setSelected(inc.id)
    }
    setShowForm(false)
    setPlaybook(form.type || '')
  }

  const updateStatus = (id: string, status: Incident['status']) => {
    persist(incidents.map(i => i.id === id ? { ...i, status, closedAt: status === 'Closed' ? now() : i.closedAt } : i))
  }

  const addTimeline = (id: string) => {
    if (!timelineEntry.description.trim()) return
    const event: TimelineEvent = { id: crypto.randomUUID(), timestamp: now(), ...timelineEntry }
    persist(incidents.map(i => i.id === id ? { ...i, timeline: [...i.timeline, event] } : i))
    setTimelineEntry({ description: '', analyst: '', action: '' })
  }

  const deleteIncident = (id: string) => { if (confirm('Delete this incident?')) { persist(incidents.filter(i => i.id !== id)); if (selected === id) setSelected(null) } }

  const selectedInc = incidents.find(i => i.id === selected)

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="section-heading">Incident Response</h2>
          <p className="section-subheading">Track incidents, follow playbooks, and document response actions</p>
        </div>
        <div className="flex gap-2 flex-wrap">
          <button onClick={() => downloadJSON(incidents, 'incidents.json')} className="btn-primary">Export JSON</button>
          <button onClick={() => downloadText(toCSV(incidents.map(i => ({ id: i.id, title: i.title, type: i.type, severity: i.severity, status: i.status, assignee: i.assignee, timestamp: i.timestamp }))), 'incidents.csv', 'text/csv')} className="btn-primary">Export CSV</button>
          <button onClick={openNew} className="btn-success">+ New Incident</button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {(['Open', 'In Progress', 'Contained', 'Eradicated', 'Resolved', 'Closed'] as const).map(s => (
          <div key={s} className="stat-card">
            <div className="text-xs text-gray-500">{s}</div>
            <div className="text-xl font-bold" style={{ color: STATUS_COLORS[s] }}>{incidents.filter(i => i.status === s).length}</div>
          </div>
        ))}
      </div>

      {showForm && (
        <div className="card border-glow-blue">
          <div className="card-header"><span className="card-title">New Incident</span></div>
          <div className="grid md:grid-cols-2 gap-4">
            <div className="md:col-span-2"><label className="text-xs text-gray-400 mb-1 block">Incident Title *</label><input className="cyber-input" value={form.title || ''} onChange={e => setForm(f => ({ ...f, title: e.target.value }))} placeholder="e.g., Ransomware infection on Finance servers" /></div>
            <div><label className="text-xs text-gray-400 mb-1 block">Type</label><select className="cyber-select w-full" value={form.type} onChange={e => setForm(f => ({ ...f, type: e.target.value }))}>{INCIDENT_TYPES.map(t => <option key={t}>{t}</option>)}</select></div>
            <div><label className="text-xs text-gray-400 mb-1 block">Severity</label><select className="cyber-select w-full" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value as Incident['severity'] }))}>{['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}</select></div>
            <div><label className="text-xs text-gray-400 mb-1 block">Assigned To</label><input className="cyber-input" value={form.assignee || ''} onChange={e => setForm(f => ({ ...f, assignee: e.target.value }))} placeholder="Analyst name" /></div>
            <div><label className="text-xs text-gray-400 mb-1 block">Affected Systems</label><input className="cyber-input" value={form.affectedSystems || ''} onChange={e => setForm(f => ({ ...f, affectedSystems: e.target.value }))} placeholder="Server01, Workstation-42, 10.0.0.5" /></div>
            <div className="md:col-span-2"><label className="text-xs text-gray-400 mb-1 block">Description</label><textarea className="cyber-textarea w-full h-20" value={form.description || ''} onChange={e => setForm(f => ({ ...f, description: e.target.value }))} placeholder="Describe the incident..." /></div>
            <div className="md:col-span-2"><label className="text-xs text-gray-400 mb-1 block">Known IOCs</label><textarea className="cyber-textarea w-full h-16" value={form.iocs || ''} onChange={e => setForm(f => ({ ...f, iocs: e.target.value }))} placeholder="One IOC per line..." /></div>
          </div>
          <div className="flex gap-2 mt-4"><button onClick={submitForm} className="btn-success">Create Incident</button><button onClick={() => setShowForm(false)} className="btn-danger">Cancel</button></div>
        </div>
      )}

      <div className="grid md:grid-cols-3 gap-4">
        {/* Incident list */}
        <div className="space-y-2">
          {incidents.length === 0 ? (
            <div className="text-center py-12 text-gray-500 text-sm">No incidents yet. Click &quot;+ New Incident&quot; to start tracking.</div>
          ) : (
            incidents.map(inc => (
              <div
                key={inc.id}
                onClick={() => { setSelected(inc.id); setActiveTab('details'); setPlaybook(inc.type) }}
                className={`p-3 rounded-lg cursor-pointer transition-all ${selected === inc.id ? 'border-glow-blue' : ''}`}
                style={{ background: 'rgba(10,20,40,0.6)', border: `1px solid ${selected === inc.id ? 'rgba(0,212,255,0.4)' : 'rgba(0,212,255,0.08)'}` }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="text-sm font-medium text-gray-200 truncate">{inc.title}</div>
                    <div className="text-xs text-gray-500 mt-0.5">{inc.type}</div>
                  </div>
                  <span className={`badge badge-${inc.severity.toLowerCase()} shrink-0`}>{inc.severity}</span>
                </div>
                <div className="flex items-center gap-2 mt-2">
                  <span className="text-xs" style={{ color: STATUS_COLORS[inc.status] }}>● {inc.status}</span>
                  <span className="text-xs text-gray-600">{formatDate(inc.timestamp)}</span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Detail panel */}
        <div className="md:col-span-2">
          {!selectedInc ? (
            <div className="card h-full flex items-center justify-center text-gray-500 text-sm">
              Select an incident to view details
            </div>
          ) : (
            <div className="card space-y-4">
              <div className="flex items-start justify-between flex-wrap gap-2">
                <div>
                  <div className="text-base font-semibold text-gray-200">{selectedInc.title}</div>
                  <div className="text-xs text-gray-500 mt-0.5">{selectedInc.type} · Created {formatDate(selectedInc.timestamp)}</div>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <select className="text-xs py-1 px-2 rounded" style={{ background: 'rgba(10,20,40,0.8)', border: '1px solid rgba(0,212,255,0.2)', color: STATUS_COLORS[selectedInc.status] }} value={selectedInc.status} onChange={e => updateStatus(selectedInc.id, e.target.value as Incident['status'])}>
                    {['Open', 'In Progress', 'Contained', 'Eradicated', 'Resolved', 'Closed'].map(s => <option key={s}>{s}</option>)}
                  </select>
                  <button onClick={() => { setForm({ ...selectedInc }); setShowForm(true) }} className="btn-primary text-xs py-1">Edit</button>
                  <button onClick={() => deleteIncident(selectedInc.id)} className="btn-danger text-xs py-1">Delete</button>
                </div>
              </div>

              {/* Tabs */}
              <div className="flex gap-2">
                {(['details', 'timeline', 'playbook'] as const).map(t => (
                  <button key={t} onClick={() => setActiveTab(t)} className={`tab-btn capitalize ${activeTab === t ? 'active' : ''}`}>{t}</button>
                ))}
              </div>

              {activeTab === 'details' && (
                <div className="space-y-3">
                  {[
                    ['Severity', <span key="s" className={`badge badge-${selectedInc.severity.toLowerCase()}`}>{selectedInc.severity}</span>],
                    ['Assignee', selectedInc.assignee || '—'],
                    ['Affected Systems', selectedInc.affectedSystems || '—'],
                    ['Description', selectedInc.description || '—'],
                    ['IOCs', <pre key="ioc" className="font-mono text-xs whitespace-pre-wrap text-gray-300">{selectedInc.iocs || 'None'}</pre>],
                  ].map(([label, value], i) => (
                    <div key={i} className="flex items-start gap-3 py-2 border-b" style={{ borderColor: 'rgba(0,212,255,0.06)' }}>
                      <span className="text-xs text-gray-500 w-32 shrink-0">{label}</span>
                      <div className="text-sm text-gray-300">{value}</div>
                    </div>
                  ))}
                </div>
              )}

              {activeTab === 'timeline' && (
                <div className="space-y-3">
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {selectedInc.timeline.map(ev => (
                      <div key={ev.id} className="flex gap-3 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)' }}>
                        <div className="text-xs text-gray-600 whitespace-nowrap w-32 shrink-0">{formatDate(ev.timestamp)}</div>
                        <div>
                          {ev.action && <span className="badge badge-info mb-1 block w-fit">{ev.action}</span>}
                          <div className="text-xs text-gray-300">{ev.description}</div>
                          {ev.analyst && <div className="text-xs text-gray-600 mt-0.5">— {ev.analyst}</div>}
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="border-t pt-3" style={{ borderColor: 'rgba(0,212,255,0.1)' }}>
                    <div className="text-xs font-semibold text-blue-400 mb-2">Add Timeline Entry</div>
                    <div className="grid grid-cols-2 gap-2 mb-2">
                      <input className="cyber-input text-xs" value={timelineEntry.analyst} onChange={e => setTimelineEntry(t => ({ ...t, analyst: e.target.value }))} placeholder="Analyst name" />
                      <input className="cyber-input text-xs" value={timelineEntry.action} onChange={e => setTimelineEntry(t => ({ ...t, action: e.target.value }))} placeholder="Action type (e.g., Contain, Analyze)" />
                    </div>
                    <div className="flex gap-2">
                      <input className="cyber-input text-xs flex-1" value={timelineEntry.description} onChange={e => setTimelineEntry(t => ({ ...t, description: e.target.value }))} placeholder="Describe the action taken..." onKeyDown={e => e.key === 'Enter' && addTimeline(selectedInc.id)} />
                      <button onClick={() => addTimeline(selectedInc.id)} className="btn-primary text-xs">Add</button>
                    </div>
                  </div>
                </div>
              )}

              {activeTab === 'playbook' && (
                <div className="space-y-3">
                  <div className="flex gap-2 flex-wrap">
                    {Object.keys(PLAYBOOKS).map(t => (
                      <button key={t} onClick={() => setPlaybook(t)} className={`tab-btn text-xs ${playbook === t ? 'active' : ''}`}>{t}</button>
                    ))}
                  </div>
                  {playbook && PLAYBOOKS[playbook] && (
                    <div className="space-y-3">
                      {PLAYBOOKS[playbook].map((phase, pi) => (
                        <div key={pi} className="playbook-step">
                          <div>
                            <div className="text-sm font-semibold text-blue-300 mb-2">{phase.phase}</div>
                            <ul className="space-y-1.5">
                              {phase.steps.map((step, si) => (
                                <li key={si} className="flex items-start gap-2 text-xs text-gray-300">
                                  <span className="text-blue-400 shrink-0 mt-0.5">▸</span>
                                  {step}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  {(!playbook || !PLAYBOOKS[playbook]) && (
                    <div className="text-center text-gray-500 text-sm py-6">Select an incident type above to load the response playbook</div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
