'use client'

import React, { useState, useEffect } from 'react'
import { lsGet, lsSet } from '@/lib/utils'

interface CheckItem {
  id: string
  text: string
  priority: 'Critical' | 'High' | 'Medium' | 'Low'
  reference?: string
}

interface ChecklistCategory {
  name: string
  items: CheckItem[]
}

interface ChecklistTemplate {
  id: string
  name: string
  description: string
  categories: ChecklistCategory[]
}

const CHECKLISTS: ChecklistTemplate[] = [
  {
    id: 'windows-hardening',
    name: 'Windows Server Hardening',
    description: 'Security hardening checklist for Windows Server environments',
    categories: [
      {
        name: 'Authentication & Access Control',
        items: [
          { id: 'win-1', text: 'Enforce complex password policy (min 12 chars, complexity enabled)', priority: 'Critical', reference: 'CIS Control 5.2' },
          { id: 'win-2', text: 'Enable account lockout policy (threshold: 5 attempts, duration: 30 min)', priority: 'Critical', reference: 'CIS Control 5.3' },
          { id: 'win-3', text: 'Disable or rename local Administrator account', priority: 'High', reference: 'CIS Level 1' },
          { id: 'win-4', text: 'Implement MFA for all privileged accounts', priority: 'Critical' },
          { id: 'win-5', text: 'Enable Protected Users security group for privileged accounts', priority: 'High' },
          { id: 'win-6', text: 'Configure LAPS (Local Administrator Password Solution)', priority: 'High' },
          { id: 'win-7', text: 'Disable LM and NTLMv1 authentication', priority: 'High', reference: 'CIS L1' },
          { id: 'win-8', text: 'Enable Credential Guard (HVCI)', priority: 'Critical' },
        ]
      },
      {
        name: 'Patch Management',
        items: [
          { id: 'win-9', text: 'Enable automatic Windows Updates or configure WSUS', priority: 'Critical' },
          { id: 'win-10', text: 'Patch all critical/high vulnerabilities within 14 days', priority: 'Critical' },
          { id: 'win-11', text: 'Apply OS patches within 30 days of release', priority: 'High' },
          { id: 'win-12', text: 'Maintain current anti-malware definitions', priority: 'Critical' },
        ]
      },
      {
        name: 'Network Security',
        items: [
          { id: 'win-13', text: 'Enable Windows Firewall on all profiles (Domain, Private, Public)', priority: 'Critical' },
          { id: 'win-14', text: 'Disable SMBv1 protocol', priority: 'Critical', reference: 'MS17-010' },
          { id: 'win-15', text: 'Enable SMB signing on all DCs and servers', priority: 'High' },
          { id: 'win-16', text: 'Disable LLMNR and NetBIOS if not needed', priority: 'High' },
          { id: 'win-17', text: 'Block unused ports and services via firewall rules', priority: 'High' },
          { id: 'win-18', text: 'Disable Remote Registry if not required', priority: 'Medium' },
        ]
      },
      {
        name: 'Audit & Logging',
        items: [
          { id: 'win-19', text: 'Enable Advanced Audit Policy: Account Logon, Logon, Object Access', priority: 'Critical' },
          { id: 'win-20', text: 'Configure PowerShell ScriptBlock Logging (Event 4104)', priority: 'Critical' },
          { id: 'win-21', text: 'Enable PowerShell Module Logging and Transcription', priority: 'High' },
          { id: 'win-22', text: 'Forward logs to SIEM (Windows Event Forwarding or agent)', priority: 'Critical' },
          { id: 'win-23', text: 'Set security log size to minimum 4GB', priority: 'High' },
          { id: 'win-24', text: 'Enable Process Creation Logging with command line (Event 4688)', priority: 'Critical' },
        ]
      },
      {
        name: 'Endpoint Protection',
        items: [
          { id: 'win-25', text: 'Deploy EDR solution (Windows Defender ATP or third-party)', priority: 'Critical' },
          { id: 'win-26', text: 'Enable Windows Defender Antivirus (or third-party equivalent)', priority: 'Critical' },
          { id: 'win-27', text: 'Enable Attack Surface Reduction (ASR) rules', priority: 'High', reference: 'Microsoft MDAV' },
          { id: 'win-28', text: 'Enable Exploit Protection (EMET equivalent)', priority: 'High' },
          { id: 'win-29', text: 'Configure AppLocker or WDAC for application whitelisting', priority: 'High' },
          { id: 'win-30', text: 'Disable macros in Microsoft Office for standard users', priority: 'Critical' },
        ]
      },
    ]
  },
  {
    id: 'linux-hardening',
    name: 'Linux Server Hardening',
    description: 'Security hardening checklist for Linux servers (CIS Benchmarks aligned)',
    categories: [
      {
        name: 'Initial Configuration',
        items: [
          { id: 'lx-1', text: 'Set filesystem permissions on sensitive files (/etc/passwd, /etc/shadow)', priority: 'Critical' },
          { id: 'lx-2', text: 'Disable root login via SSH', priority: 'Critical', reference: 'CIS 5.2.8' },
          { id: 'lx-3', text: 'Configure SSH to use key-based authentication only', priority: 'Critical' },
          { id: 'lx-4', text: 'Change default SSH port (22) to non-standard port', priority: 'Medium' },
          { id: 'lx-5', text: 'Enable SSH protocol v2 only', priority: 'High' },
          { id: 'lx-6', text: 'Set BIOS/GRUB password for physical security', priority: 'Medium' },
        ]
      },
      {
        name: 'Access Control',
        items: [
          { id: 'lx-7', text: 'Implement principle of least privilege for all accounts', priority: 'Critical' },
          { id: 'lx-8', text: 'Configure sudo to log all commands', priority: 'High' },
          { id: 'lx-9', text: 'Set password complexity and aging policies (pam_pwquality)', priority: 'High' },
          { id: 'lx-10', text: 'Disable unused accounts and remove unnecessary users', priority: 'High' },
          { id: 'lx-11', text: 'Configure PAM (Pluggable Authentication Modules) securely', priority: 'High' },
          { id: 'lx-12', text: 'Restrict su access to wheel group only', priority: 'Medium' },
        ]
      },
      {
        name: 'Network Security',
        items: [
          { id: 'lx-13', text: 'Enable and configure UFW or iptables firewall', priority: 'Critical' },
          { id: 'lx-14', text: 'Disable IPv6 if not required', priority: 'Low' },
          { id: 'lx-15', text: 'Enable TCP SYN cookies to prevent SYN flood attacks', priority: 'Medium' },
          { id: 'lx-16', text: 'Disable IP forwarding if not a router', priority: 'High' },
          { id: 'lx-17', text: 'Enable ICMP ignore broadcasts', priority: 'Low' },
          { id: 'lx-18', text: 'Configure fail2ban for SSH brute force protection', priority: 'High' },
        ]
      },
      {
        name: 'Audit & Logging',
        items: [
          { id: 'lx-19', text: 'Install and configure auditd with comprehensive rules', priority: 'Critical' },
          { id: 'lx-20', text: 'Enable rsyslog or journald with remote syslog forwarding', priority: 'Critical' },
          { id: 'lx-21', text: 'Monitor /etc/passwd, /etc/shadow changes via auditd', priority: 'Critical' },
          { id: 'lx-22', text: 'Audit all privileged command execution (sudo, su)', priority: 'Critical' },
          { id: 'lx-23', text: 'Set log rotation with adequate retention (90+ days)', priority: 'High' },
          { id: 'lx-24', text: 'Monitor cron jobs and at commands', priority: 'High' },
        ]
      },
      {
        name: 'Services & Software',
        items: [
          { id: 'lx-25', text: 'Remove or disable all unnecessary services', priority: 'High' },
          { id: 'lx-26', text: 'Keep OS and packages updated (configure unattended-upgrades)', priority: 'Critical' },
          { id: 'lx-27', text: 'Enable SELinux or AppArmor in enforcing mode', priority: 'High' },
          { id: 'lx-28', text: 'Configure rkhunter or chkrootkit for rootkit detection', priority: 'High' },
          { id: 'lx-29', text: 'Enable file integrity monitoring (AIDE, Tripwire)', priority: 'High' },
          { id: 'lx-30', text: 'Disable core dumps for setuid programs', priority: 'Medium' },
        ]
      },
    ]
  },
  {
    id: 'cloud-security',
    name: 'Cloud Security (AWS/Azure/GCP)',
    description: 'Security controls for cloud infrastructure',
    categories: [
      {
        name: 'Identity & Access Management',
        items: [
          { id: 'cl-1', text: 'Enable MFA for all IAM/cloud users, especially root/admin', priority: 'Critical' },
          { id: 'cl-2', text: 'Rotate access keys every 90 days', priority: 'High' },
          { id: 'cl-3', text: 'Implement least privilege IAM policies', priority: 'Critical' },
          { id: 'cl-4', text: 'Disable/delete unused IAM users and service accounts', priority: 'High' },
          { id: 'cl-5', text: 'Use roles/service accounts instead of long-term credentials', priority: 'High' },
          { id: 'cl-6', text: 'Enable AWS Organizations SCPs or Azure Management Groups', priority: 'High' },
        ]
      },
      {
        name: 'Logging & Monitoring',
        items: [
          { id: 'cl-7', text: 'Enable CloudTrail/Activity Logs in all regions', priority: 'Critical' },
          { id: 'cl-8', text: 'Enable VPC Flow Logs for all VPCs', priority: 'Critical' },
          { id: 'cl-9', text: 'Enable AWS GuardDuty or Azure Defender for threat detection', priority: 'Critical' },
          { id: 'cl-10', text: 'Configure CloudWatch/Azure Monitor alerts for suspicious activity', priority: 'High' },
          { id: 'cl-11', text: 'Enable S3/Storage bucket access logging', priority: 'High' },
          { id: 'cl-12', text: 'Export cloud logs to SIEM for centralized analysis', priority: 'High' },
        ]
      },
      {
        name: 'Network Security',
        items: [
          { id: 'cl-13', text: 'Restrict Security Groups/NSGs to minimum required access', priority: 'Critical' },
          { id: 'cl-14', text: 'Block all public access to S3 buckets unless required', priority: 'Critical' },
          { id: 'cl-15', text: 'Use private subnets for databases and internal resources', priority: 'Critical' },
          { id: 'cl-16', text: 'Enable AWS WAF or Azure WAF for public web applications', priority: 'High' },
          { id: 'cl-17', text: 'Configure VPC endpoints to avoid internet routing', priority: 'Medium' },
          { id: 'cl-18', text: 'Enable DDoS protection (AWS Shield, Azure DDoS Protection)', priority: 'High' },
        ]
      },
      {
        name: 'Data Protection',
        items: [
          { id: 'cl-19', text: 'Enable encryption at rest for all storage services', priority: 'Critical' },
          { id: 'cl-20', text: 'Enable encryption in transit (TLS) for all data', priority: 'Critical' },
          { id: 'cl-21', text: 'Use KMS/Key Vault for encryption key management', priority: 'High' },
          { id: 'cl-22', text: 'Enable versioning and MFA delete on S3 buckets with sensitive data', priority: 'High' },
          { id: 'cl-23', text: 'Configure backup and disaster recovery for critical resources', priority: 'Critical' },
          { id: 'cl-24', text: 'Enable CloudTrail log file integrity validation', priority: 'Medium' },
        ]
      },
    ]
  },
  {
    id: 'incident-readiness',
    name: 'Incident Response Readiness',
    description: 'Preparedness checklist for Blue Team incident response',
    categories: [
      {
        name: 'Planning & Documentation',
        items: [
          { id: 'ir-1', text: 'Documented Incident Response Plan (reviewed annually)', priority: 'Critical' },
          { id: 'ir-2', text: 'Up-to-date contact list for stakeholders, legal, PR, law enforcement', priority: 'Critical' },
          { id: 'ir-3', text: 'Playbooks for top 5 most likely incident types', priority: 'Critical' },
          { id: 'ir-4', text: 'Data classification policy defining sensitive data types', priority: 'High' },
          { id: 'ir-5', text: 'Asset inventory with criticality ratings', priority: 'Critical' },
          { id: 'ir-6', text: 'Network topology diagrams (current)', priority: 'High' },
        ]
      },
      {
        name: 'Technical Preparation',
        items: [
          { id: 'ir-7', text: 'SIEM deployed with comprehensive log sources', priority: 'Critical' },
          { id: 'ir-8', text: 'EDR deployed on all endpoints', priority: 'Critical' },
          { id: 'ir-9', text: 'Network monitoring and packet capture capability', priority: 'High' },
          { id: 'ir-10', text: 'Forensic toolkit ready (memory capture, disk imaging tools)', priority: 'High' },
          { id: 'ir-11', text: 'Out-of-band communication channel for IR team', priority: 'High' },
          { id: 'ir-12', text: 'Tested backup and restore procedures', priority: 'Critical' },
        ]
      },
      {
        name: 'Team & Process',
        items: [
          { id: 'ir-13', text: 'Defined IR team roles and responsibilities', priority: 'Critical' },
          { id: 'ir-14', text: 'IR tabletop exercise conducted in last 12 months', priority: 'High' },
          { id: 'ir-15', text: 'Relationship established with MSSP or external IR firm', priority: 'High' },
          { id: 'ir-16', text: 'Legal counsel familiar with cyber incident requirements', priority: 'Critical' },
          { id: 'ir-17', text: 'Regulatory reporting requirements understood (GDPR, HIPAA, etc.)', priority: 'Critical' },
          { id: 'ir-18', text: 'Cyber insurance policy in place and understood', priority: 'High' },
        ]
      },
    ]
  },
]

export default function SecurityChecklists() {
  const [selectedChecklist, setSelectedChecklist] = useState(CHECKLISTS[0].id)
  const [checked, setChecked] = useState<Record<string, boolean>>({})
  const [filter, setFilter] = useState<'all' | 'incomplete' | 'complete'>('all')

  useEffect(() => {
    setChecked(lsGet<Record<string, boolean>>('bt_checklists', {}))
  }, [])

  const toggle = (id: string) => {
    const next = { ...checked, [id]: !checked[id] }
    setChecked(next)
    lsSet('bt_checklists', next)
  }

  const checklist = CHECKLISTS.find(c => c.id === selectedChecklist)!
  const allItems = checklist.categories.flatMap(c => c.items)
  const completedCount = allItems.filter(i => checked[`${selectedChecklist}-${i.id}`]).length
  const progress = allItems.length ? Math.round((completedCount / allItems.length) * 100) : 0

  const sevColor: Record<string, string> = { Critical: '#ff4444', High: '#ff6b35', Medium: '#ffd700', Low: '#00d4ff' }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="section-heading">Security Checklists</h2>
          <p className="section-subheading">Hardening and compliance checklists (CIS Benchmarks aligned)</p>
        </div>
        <button onClick={() => { const reset = { ...checked }; allItems.forEach(i => delete reset[`${selectedChecklist}-${i.id}`]); setChecked(reset); lsSet('bt_checklists', reset) }} className="btn-danger text-xs">
          Reset Checklist
        </button>
      </div>

      {/* Checklist selector */}
      <div className="flex flex-wrap gap-2">
        {CHECKLISTS.map(c => (
          <button key={c.id} onClick={() => setSelectedChecklist(c.id)} className={`tab-btn ${selectedChecklist === c.id ? 'active' : ''}`}>
            {c.name}
          </button>
        ))}
      </div>

      {/* Progress */}
      <div className="card">
        <div className="flex items-center justify-between mb-2">
          <div>
            <div className="text-sm font-semibold text-gray-200">{checklist.name}</div>
            <div className="text-xs text-gray-500">{checklist.description}</div>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-blue-400">{progress}%</div>
            <div className="text-xs text-gray-500">{completedCount}/{allItems.length} complete</div>
          </div>
        </div>
        <div className="progress-bar h-2">
          <div className="progress-fill" style={{ width: `${progress}%`, background: progress === 100 ? '#39ff14' : progress >= 75 ? '#00d4ff' : progress >= 50 ? '#ffd700' : '#ff6b35' }} />
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-2">
        {(['all', 'incomplete', 'complete'] as const).map(f => (
          <button key={f} onClick={() => setFilter(f)} className={`tab-btn capitalize ${filter === f ? 'active' : ''}`}>{f}</button>
        ))}
        <div className="flex gap-2 ml-auto flex-wrap text-xs text-gray-500 items-center">
          {(['Critical', 'High', 'Medium', 'Low'] as const).map(s => (
            <span key={s} className="flex items-center gap-1">
              <span className="w-2 h-2 rounded-full" style={{ background: sevColor[s] }} />
              {s}
            </span>
          ))}
        </div>
      </div>

      {/* Categories */}
      <div className="space-y-4">
        {checklist.categories.map(cat => {
          const catItems = cat.items.filter(item => {
            const done = checked[`${selectedChecklist}-${item.id}`]
            if (filter === 'complete') return done
            if (filter === 'incomplete') return !done
            return true
          })
          if (catItems.length === 0) return null
          const catDone = cat.items.filter(i => checked[`${selectedChecklist}-${i.id}`]).length
          return (
            <div key={cat.name} className="card">
              <div className="flex items-center justify-between mb-3">
                <div className="card-title">{cat.name}</div>
                <div className="text-xs text-gray-500">{catDone}/{cat.items.length}</div>
              </div>
              <div className="space-y-2">
                {catItems.map(item => {
                  const key = `${selectedChecklist}-${item.id}`
                  const done = checked[key]
                  return (
                    <div key={item.id} className={`checklist-item ${done ? 'completed' : ''}`} onClick={() => toggle(key)} style={{ cursor: 'pointer' }}>
                      <div
                        className="w-5 h-5 rounded shrink-0 flex items-center justify-center mt-0.5 transition-all"
                        style={{ border: `2px solid ${done ? '#39ff14' : 'rgba(0,212,255,0.3)'}`, background: done ? 'rgba(57,255,20,0.15)' : 'transparent' }}
                      >
                        {done && <span className="text-xs" style={{ color: '#39ff14' }}>✓</span>}
                      </div>
                      <div className="flex-1">
                        <div className={`text-sm ${done ? 'line-through text-gray-500' : 'text-gray-200'}`}>{item.text}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs px-1 rounded" style={{ background: `rgba(${parseInt(sevColor[item.priority].slice(1, 3), 16)},${parseInt(sevColor[item.priority].slice(3, 5), 16)},${parseInt(sevColor[item.priority].slice(5, 7), 16)}, 0.1)`, color: sevColor[item.priority] }}>{item.priority}</span>
                          {item.reference && <span className="text-xs text-gray-600">{item.reference}</span>}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
