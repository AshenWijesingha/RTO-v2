'use client'

import React, { useState, useEffect } from 'react'
import { lsGet, lsSet, downloadText, now } from '@/lib/utils'

interface ReportData {
  title: string
  analystName: string
  organization: string
  date: string
  severity: string
  executiveSummary: string
  timeline: string
  affectedSystems: string
  attackVector: string
  iocs: string
  mitigations: string
  recommendations: string
  lessonsLearned: string
}

const DEFAULT_REPORT: ReportData = {
  title: '',
  analystName: '',
  organization: '',
  date: new Date().toISOString().slice(0, 10),
  severity: 'High',
  executiveSummary: '',
  timeline: '',
  affectedSystems: '',
  attackVector: '',
  iocs: '',
  mitigations: '',
  recommendations: '',
  lessonsLearned: '',
}

const TEMPLATES = {
  ransomware: {
    title: 'Ransomware Incident Report',
    executiveSummary: 'On [DATE], our Security Operations Center detected a ransomware infection affecting [NUMBER] systems in the [DEPARTMENT] department. The attack was attributed to [THREAT ACTOR/VARIANT] ransomware. Immediate containment measures were implemented, and business operations were restored within [TIMEFRAME]. Estimated impact: [SYSTEMS] systems encrypted, [DATA] of data affected.',
    timeline: `• [TIME] - Initial alert triggered by EDR/SIEM
• [TIME] - SOC analyst begins triage
• [TIME] - Ransomware confirmed, IR team activated
• [TIME] - Affected systems isolated from network
• [TIME] - Incident Commander notified
• [TIME] - Backup validation initiated
• [TIME] - Executive leadership notified
• [TIME] - Legal and compliance teams engaged
• [TIME] - Systems restored from backup
• [TIME] - Post-incident monitoring period begins`,
    attackVector: 'Initial access was achieved via [PHISHING EMAIL/RDP/VULNERABILITY]. The attacker [LATERAL MOVEMENT DESCRIPTION] before deploying the ransomware payload.',
    mitigations: `• Isolated all affected systems from the network
• Blocked identified C2 IP addresses at firewall
• Reset credentials for all affected accounts
• Applied emergency patches to exploited vulnerabilities
• Restored affected systems from verified clean backups`,
    recommendations: `• Implement MFA for all accounts, especially remote access
• Enhance email filtering to block phishing attempts
• Improve backup testing and frequency
• Conduct security awareness training focused on phishing
• Deploy or enhance EDR solution on all endpoints
• Segment network to limit lateral movement`,
    lessonsLearned: `• Detection: [WHAT WORKED/DIDN'T WORK]
• Response time: [WAS RESPONSE ADEQUATE]
• Communication: [IMPROVEMENTS NEEDED]
• Backup integrity: [BACKUP STATUS]
• Gaps identified: [LIST GAPS]`,
  },
  phishing: {
    title: 'Phishing Incident Report',
    executiveSummary: 'A targeted phishing campaign was detected affecting [NUMBER] employees. [NUMBER] users clicked the malicious link and [NUMBER] submitted credentials. Immediate response included email removal, credential resets, and MFA enforcement.',
    timeline: `• [TIME] - Phishing email received by [NUMBER] users
• [TIME] - First user report to helpdesk
• [TIME] - SOC identifies campaign via email gateway
• [TIME] - Phishing email removed from all mailboxes
• [TIME] - Affected accounts identified and credentials reset
• [TIME] - MFA enforced for affected accounts
• [TIME] - Scope of compromise assessed
• [TIME] - All-clear declared`,
    attackVector: 'The phishing email impersonated [ENTITY] and contained a link to [FAKE SITE] designed to harvest credentials.',
    mitigations: `• Removed phishing emails from all affected mailboxes
• Blocked sender domain and phishing URL at email gateway
• Reset passwords for all users who submitted credentials
• Enforced MFA immediately for affected accounts
• Reviewed and revoked suspicious OAuth application grants`,
    recommendations: `• Implement DMARC, DKIM, and SPF for all email domains
• Deploy advanced email security with sandboxing
• Conduct regular phishing simulation training
• Implement hardware security keys for high-risk accounts
• Enable mailbox audit logging`,
    lessonsLearned: `• User awareness: [TRAINING GAPS]
• Email controls: [GAPS IN FILTERING]
• Response time: [IMPROVEMENTS]
• MFA coverage: [GAPS]`,
  },
  'data-breach': {
    title: 'Data Breach Incident Report',
    executiveSummary: 'A data breach was discovered on [DATE] involving unauthorized access to [SYSTEM/DATABASE]. Approximately [NUMBER] records containing [DATA TYPE] were potentially exposed. The breach occurred between [START DATE] and [END DATE].',
    timeline: `• [DATE] - Breach discovered/reported
• [DATE] - Initial assessment completed
• [DATE] - Scope of breach determined
• [DATE] - Legal counsel engaged
• [DATE] - Regulatory notification deadline calculated
• [DATE] - Affected individuals notified
• [DATE] - Regulatory notification filed`,
    attackVector: 'Unauthorized access was gained via [METHOD]. The attacker accessed [SYSTEM] and exfiltrated [DATA TYPE].',
    mitigations: `• Closed the security gap that allowed unauthorized access
• Revoked compromised credentials
• Implemented additional access controls
• Enhanced monitoring on affected systems`,
    recommendations: `• Implement data loss prevention (DLP) solution
• Encrypt all sensitive data at rest and in transit
• Implement zero-trust network architecture
• Conduct regular data access reviews
• Enhance monitoring for data exfiltration`,
    lessonsLearned: `• Data visibility: [GAPS IN DATA CLASSIFICATION]
• Access controls: [IMPROVEMENTS NEEDED]
• Detection time: [HOW LONG BEFORE DETECTION]
• Regulatory compliance: [NOTIFICATION REQUIREMENTS MET]`,
  },
}

export default function ReportGenerator() {
  const [report, setReport] = useState<ReportData>(DEFAULT_REPORT)
  const [template, setTemplate] = useState<keyof typeof TEMPLATES | ''>('')
  const [preview, setPreview] = useState(false)

  useEffect(() => {
    const saved = lsGet<ReportData>('bt_report_draft', DEFAULT_REPORT)
    setReport(saved)
  }, [])

  const update = (field: keyof ReportData, value: string) => {
    const next = { ...report, [field]: value }
    setReport(next)
    lsSet('bt_report_draft', next)
  }

  const loadTemplate = (t: keyof typeof TEMPLATES) => {
    const tmpl = TEMPLATES[t]
    setReport(r => ({
      ...r,
      title: tmpl.title,
      executiveSummary: tmpl.executiveSummary,
      timeline: tmpl.timeline,
      attackVector: tmpl.attackVector,
      mitigations: tmpl.mitigations,
      recommendations: tmpl.recommendations,
      lessonsLearned: tmpl.lessonsLearned,
    }))
    setTemplate(t)
  }

  const generateReport = () => {
    const r = report
    return `================================================================================
INCIDENT RESPONSE REPORT
================================================================================

TITLE:          ${r.title || 'Untitled Incident Report'}
DATE:           ${r.date}
ANALYST:        ${r.analystName || 'N/A'}
ORGANIZATION:   ${r.organization || 'N/A'}
SEVERITY:       ${r.severity}
GENERATED:      ${new Date().toLocaleString()}

================================================================================
1. EXECUTIVE SUMMARY
================================================================================

${r.executiveSummary || 'Not provided.'}

================================================================================
2. INCIDENT TIMELINE
================================================================================

${r.timeline || 'Not provided.'}

================================================================================
3. AFFECTED SYSTEMS
================================================================================

${r.affectedSystems || 'Not provided.'}

================================================================================
4. ATTACK VECTOR & METHODOLOGY
================================================================================

${r.attackVector || 'Not provided.'}

================================================================================
5. INDICATORS OF COMPROMISE (IOCs)
================================================================================

${r.iocs || 'None identified.'}

================================================================================
6. CONTAINMENT & ERADICATION ACTIONS
================================================================================

${r.mitigations || 'Not provided.'}

================================================================================
7. RECOMMENDATIONS
================================================================================

${r.recommendations || 'Not provided.'}

================================================================================
8. LESSONS LEARNED
================================================================================

${r.lessonsLearned || 'Not provided.'}

================================================================================
REPORT CLASSIFICATION: CONFIDENTIAL - FOR INTERNAL USE ONLY
Report generated by Blue Team Cyber Dashboard v2
================================================================================`
  }

  const downloadReport = () => {
    downloadText(generateReport(), `incident-report-${report.date}-${now().replace(/[:.]/g, '-')}.txt`)
  }

  const downloadMarkdown = () => {
    const r = report
    const md = `# ${r.title || 'Incident Report'}

**Date:** ${r.date}  
**Analyst:** ${r.analystName || 'N/A'}  
**Organization:** ${r.organization || 'N/A'}  
**Severity:** ${r.severity}  

---

## 1. Executive Summary

${r.executiveSummary || '*Not provided.*'}

## 2. Incident Timeline

${r.timeline || '*Not provided.*'}

## 3. Affected Systems

${r.affectedSystems || '*Not provided.*'}

## 4. Attack Vector & Methodology

${r.attackVector || '*Not provided.*'}

## 5. Indicators of Compromise (IOCs)

\`\`\`
${r.iocs || 'None identified.'}
\`\`\`

## 6. Containment & Eradication Actions

${r.mitigations || '*Not provided.*'}

## 7. Recommendations

${r.recommendations || '*Not provided.*'}

## 8. Lessons Learned

${r.lessonsLearned || '*Not provided.*'}

---

*Report generated by Blue Team Cyber Dashboard v2 — CONFIDENTIAL*`
    downloadText(md, `incident-report-${r.date}.md`, 'text/markdown')
  }

  const fields: { key: keyof ReportData; label: string; multiline?: boolean; placeholder?: string }[] = [
    { key: 'executiveSummary', label: 'Executive Summary', multiline: true, placeholder: 'High-level description of the incident for non-technical stakeholders...' },
    { key: 'timeline', label: 'Incident Timeline', multiline: true, placeholder: 'Chronological sequence of events...' },
    { key: 'affectedSystems', label: 'Affected Systems', multiline: true, placeholder: 'List of affected hosts, IPs, applications...' },
    { key: 'attackVector', label: 'Attack Vector & Methodology', multiline: true, placeholder: 'How the attacker gained access and what they did...' },
    { key: 'iocs', label: 'Indicators of Compromise (IOCs)', multiline: true, placeholder: 'IPs, domains, hashes, file names...' },
    { key: 'mitigations', label: 'Containment & Eradication Actions', multiline: true, placeholder: 'Actions taken to contain and eradicate the threat...' },
    { key: 'recommendations', label: 'Recommendations', multiline: true, placeholder: 'Security improvements to prevent recurrence...' },
    { key: 'lessonsLearned', label: 'Lessons Learned', multiline: true, placeholder: 'What worked, what didn\'t, gaps identified...' },
  ]

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="section-heading">Report Generator</h2>
          <p className="section-subheading">Generate professional incident response and security assessment reports</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setPreview(!preview)} className="btn-primary">{preview ? 'Edit Mode' : 'Preview'}</button>
          <button onClick={downloadReport} className="btn-primary">Download .txt</button>
          <button onClick={downloadMarkdown} className="btn-primary">Download .md</button>
        </div>
      </div>

      {/* Template selector */}
      <div className="card">
        <div className="card-header"><span className="card-title">Report Templates</span></div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => { setReport(DEFAULT_REPORT); setTemplate('') }} className={`tab-btn ${template === '' ? 'active' : ''}`}>Blank</button>
          {(Object.keys(TEMPLATES) as (keyof typeof TEMPLATES)[]).map(t => (
            <button key={t} onClick={() => loadTemplate(t)} className={`tab-btn capitalize ${template === t ? 'active' : ''}`}>
              {t.replace('-', ' ')}
            </button>
          ))}
        </div>
      </div>

      {preview ? (
        <div className="card">
          <pre className="code-block text-xs whitespace-pre-wrap overflow-x-auto">{generateReport()}</pre>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Basic info */}
          <div className="card">
            <div className="card-header"><span className="card-title">Report Header</span></div>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Report Title</label>
                <input className="cyber-input" value={report.title} onChange={e => update('title', e.target.value)} placeholder="e.g., Ransomware Incident Report – Finance Department" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Incident Date</label>
                <input type="date" className="cyber-input" value={report.date} onChange={e => update('date', e.target.value)} />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Lead Analyst</label>
                <input className="cyber-input" value={report.analystName} onChange={e => update('analystName', e.target.value)} placeholder="Your name" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Organization</label>
                <input className="cyber-input" value={report.organization} onChange={e => update('organization', e.target.value)} placeholder="Company name" />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1 block">Severity</label>
                <select className="cyber-select w-full" value={report.severity} onChange={e => update('severity', e.target.value)}>
                  {['Critical', 'High', 'Medium', 'Low'].map(s => <option key={s}>{s}</option>)}
                </select>
              </div>
            </div>
          </div>

          {/* Content sections */}
          {fields.map(f => (
            <div key={f.key} className="card">
              <div className="card-header"><span className="card-title">{f.label}</span></div>
              <textarea
                className="cyber-textarea w-full h-28"
                value={report[f.key]}
                onChange={e => update(f.key, e.target.value)}
                placeholder={f.placeholder}
              />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
