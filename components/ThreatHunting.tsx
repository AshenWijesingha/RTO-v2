'use client'

import React, { useState } from 'react'
import { copyToClipboard } from '@/lib/utils'

interface Technique {
  id: string
  name: string
  tactic: string
  description: string
  detection: string[]
  hunting: string
  mitigations: string[]
  dataSource: string[]
}

const TACTICS = ['Initial Access', 'Execution', 'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement', 'Collection', 'Exfiltration', 'Command & Control', 'Impact']

const TECHNIQUES: Technique[] = [
  {
    id: 'T1566',
    name: 'Phishing',
    tactic: 'Initial Access',
    description: 'Adversaries send phishing messages to gain access to victim systems. Includes spearphishing with attachments, links, or via services.',
    detection: ['Monitor email for suspicious attachments and links', 'Detect execution of downloaded files', 'Monitor for process spawned from email clients', 'Review email gateway logs for unusual senders'],
    hunting: `// Hunt for processes spawned by email clients (Outlook, Thunderbird)
// Splunk
index=windows EventCode=4688
| where parent_process_name IN ("outlook.exe", "thunderbird.exe", "winmail.exe")
| where process_name NOT IN ("splunk-*.exe", "antivirus.exe")
| table _time, host, user, parent_process_name, process_name, process_id`,
    mitigations: ['User security awareness training', 'Email security gateway with sandbox', 'Anti-phishing policies and filtering', 'MFA for all accounts', 'Block macro execution in Office documents'],
    dataSource: ['Email Gateway Logs', 'Endpoint Process Creation', 'Network Traffic', 'File Creation Events'],
  },
  {
    id: 'T1059',
    name: 'Command and Scripting Interpreter',
    tactic: 'Execution',
    description: 'Adversaries use scripting interpreters (PowerShell, cmd, bash, Python) to execute commands and scripts.',
    detection: ['Monitor PowerShell with ScriptBlock logging (Event 4104)', 'Detect obfuscated commands and encoded payloads', 'Monitor for unusual child processes of scripting engines', 'Review command-line arguments for suspicious patterns'],
    hunting: `// Hunt for encoded PowerShell execution
// Splunk
index=windows EventCode=4688
| where process_name="powershell.exe"
| where match(process_cmdline, "(?i)(-enc|-EncodedCommand|-ec)")
| eval decoded=base64decode(mvindex(split(process_cmdline," "),-1))
| table _time, host, user, process_cmdline, decoded`,
    mitigations: ['Constrained Language Mode for PowerShell', 'Application control (Windows Defender App Control)', 'Enable Script Block Logging', 'AMSI integration', 'Disable unnecessary scripting engines'],
    dataSource: ['Process Creation', 'Script Execution Logs', 'PowerShell Logs', 'Command History'],
  },
  {
    id: 'T1547',
    name: 'Boot or Logon Autostart Execution',
    tactic: 'Persistence',
    description: 'Adversaries configure system settings to automatically execute programs during system boot or user logon.',
    detection: ['Monitor Registry keys: Run, RunOnce, Services', 'Detect new startup items and scheduled tasks', 'Monitor changes to startup folders', 'Audit new services and drivers'],
    hunting: `// Hunt for new Registry Run key entries
// Splunk
index=windows EventCode=4657
| where Object_Value_Name IN ("Run","RunOnce","RunServices","RunServicesOnce")
| where Object_Name LIKE "%\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\%"
| table _time, host, user, Object_Name, Object_Value_Name, New_Value`,
    mitigations: ['Monitor and limit autostart locations', 'Application whitelisting for startup items', 'Secure boot and integrity checking', 'Restrict registry modification permissions'],
    dataSource: ['Registry Modification', 'File Creation', 'Process Creation', 'Scheduled Task Logs'],
  },
  {
    id: 'T1548',
    name: 'Abuse Elevation Control Mechanism',
    tactic: 'Privilege Escalation',
    description: 'Adversaries bypass UAC or sudo to elevate privileges, including UAC bypass techniques.',
    detection: ['Monitor for UAC bypass attempts', 'Detect processes with elevated privileges from low-privilege parents', 'Monitor auto-elevating binaries (fodhelper.exe, etc.)', 'Review for unexpected use of sudo/su on Linux'],
    hunting: `// Hunt for UAC bypass via fodhelper
// Splunk
index=windows EventCode=4688
| where parent_process_name="fodhelper.exe" OR parent_process_name="eventvwr.exe"
| table _time, host, user, parent_process_name, process_name, process_cmdline`,
    mitigations: ['Enable UAC to highest setting', 'Remove local admin rights from standard users', 'Monitor and audit privileged account usage', 'Implement Just-In-Time (JIT) access'],
    dataSource: ['Process Creation', 'Windows Event Logs', 'Registry Modification', 'Token Activity'],
  },
  {
    id: 'T1055',
    name: 'Process Injection',
    tactic: 'Defense Evasion',
    description: 'Adversaries inject malicious code into legitimate running processes to evade defenses and elevate privileges.',
    detection: ['Monitor for unusual cross-process memory writes', 'Detect CreateRemoteThread and WriteProcessMemory API calls', 'Identify processes with unusual parent-child relationships', 'Monitor for hollowed processes'],
    hunting: `// Hunt for suspicious process injection indicators
// Splunk
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=8
| where SourceImage != TargetImage
| where NOT match(SourceImage, "(?i)(antivirus|defender|chrome|firefox)")
| stats count by SourceImage, TargetImage
| where count > 3
| sort -count`,
    mitigations: ['Enable Windows Defender Credential Guard', 'Use EDR solutions with injection detection', 'Enable Protected Process Light for LSASS', 'Implement process integrity monitoring'],
    dataSource: ['Sysmon (Event 8)', 'API Monitoring', 'Process Memory', 'EDR Telemetry'],
  },
  {
    id: 'T1003',
    name: 'OS Credential Dumping',
    tactic: 'Credential Access',
    description: 'Adversaries dump credentials from OS and software (LSASS, SAM, NTDS, browser credentials).',
    detection: ['Monitor for LSASS memory access (Sysmon Event 10)', 'Detect secretsdump, Mimikatz patterns', 'Monitor Volume Shadow Copy access', 'Alert on ntdsutil.exe execution', 'Detect access to SAM and SECURITY registry hives'],
    hunting: `// Hunt for LSASS credential access
// Splunk (Sysmon)
index=windows source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
| where TargetImage LIKE "%lsass.exe"
| where NOT match(SourceImage, "(?i)(antivirus|defender|mssense|csrss|winlogon|services)")
| table _time, host, SourceImage, TargetImage, GrantedAccess, CallTrace`,
    mitigations: ['Enable Windows Defender Credential Guard', 'Protected LSASS (RunAsPPL)', 'Limit who can access LSASS', 'Use EDR with credential theft prevention', 'Implement MFA to limit impact of stolen credentials'],
    dataSource: ['Sysmon (Event 10)', 'Windows Security Events', 'EDR Telemetry', 'File Access Logs'],
  },
  {
    id: 'T1018',
    name: 'Remote System Discovery',
    tactic: 'Discovery',
    description: 'Adversaries enumerate remote systems using tools like net view, ping sweeps, nmap, and Active Directory queries.',
    detection: ['Monitor for network scanning from internal hosts', 'Detect unusual LDAP queries to domain controllers', 'Alert on net.exe with /domain flag', 'Monitor for ping floods from single host'],
    hunting: `// Hunt for network discovery activity
// Splunk
index=windows EventCode=4688
| where process_name IN ("net.exe", "net1.exe", "ping.exe", "arp.exe", "nslookup.exe", "nltest.exe")
| stats count values(process_cmdline) as cmds by host, user, process_name
| where count > 10
| sort -count`,
    mitigations: ['Network segmentation to limit blast radius', 'Monitor and alert on discovery commands', 'Limit AD query permissions for standard users', 'Implement deception technologies (honeypots)'],
    dataSource: ['Process Creation', 'Network Traffic', 'Windows Security Events', 'LDAP Logs'],
  },
  {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries use legitimate remote services (RDP, SMB, WMI, SSH, WinRM) to laterally move.',
    detection: ['Monitor for unusual RDP connections (Event 4624 logon type 10)', 'Detect SMB connections to multiple hosts in short time', 'Alert on WMI execution from remote sources', 'Monitor for Pass-the-Hash indicators'],
    hunting: `// Hunt for lateral movement via SMB
// Splunk
index=windows EventCode=4624
| where Logon_Type=3 AND src_ip!="127.0.0.1"
| stats count dc(dest_host) as hosts_accessed by src_ip, user
| where hosts_accessed > 5
| sort -hosts_accessed`,
    mitigations: ['Limit RDP access to authorized users and IPs', 'Disable SMBv1', 'Implement network segmentation', 'Use PAM for privileged access', 'Deploy CrowdStrike or similar EDR'],
    dataSource: ['Windows Security Events', 'Network Logs', 'Authentication Logs', 'Sysmon'],
  },
  {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description: 'Adversaries exfiltrate data over the existing C2 channel, often using encrypted protocols to evade detection.',
    detection: ['Monitor for large outbound transfers to external IPs', 'Detect beaconing patterns to external IPs', 'Alert on unusual use of cloud storage APIs', 'Monitor for DNS queries to newly registered domains'],
    hunting: `// Hunt for large data exfiltration via proxy
// Splunk
index=proxy
| stats sum(bytes_out) as total_out by src_ip, dest_host
| where total_out > 52428800
| eval MB = round(total_out/1048576, 2)
| lookup threat_intel_ips ip as dest_ip OUTPUT verdict
| where NOT cidrmatch("10.0.0.0/8", dest_host)
| sort -MB`,
    mitigations: ['DLP solutions for data discovery and blocking', 'Proxy with SSL inspection', 'Egress filtering and firewall rules', 'Alert on large outbound transfers', 'Monitor cloud storage usage'],
    dataSource: ['Network Traffic', 'Proxy Logs', 'Firewall Logs', 'DNS Logs', 'DLP Alerts'],
  },
  {
    id: 'T1486',
    name: 'Data Encrypted for Impact',
    tactic: 'Impact',
    description: 'Adversaries encrypt files on target systems to make them inaccessible (ransomware).',
    detection: ['Monitor for high-volume file modification events', 'Detect file extensions associated with ransomware', 'Alert on deletion of shadow copies (vssadmin)', 'Monitor for ransom note creation (readme, decrypt, recover)'],
    hunting: `// Hunt for ransomware encryption activity
// Splunk
index=windows EventCode=4663 Object_Type=File
| rex field=Object_Name "\.(?<ext>[^.]+)$"
| where ext IN ("encrypted","locked","crypt","enc","crypto","zepto","locky","aes")
    OR match(Object_Name, "(?i)(readme|recover|decrypt|ransom)")
| stats count by host, user
| where count > 10
| sort -count`,
    mitigations: ['Offline immutable backups', 'Ransomware-specific EDR controls', 'Restrict execution from user-writable directories', 'Network segmentation to limit spread', 'User privilege minimization'],
    dataSource: ['File System Audit Logs', 'Windows Security Events', 'VSS Activity', 'EDR Telemetry'],
  },
]

export default function ThreatHunting() {
  const [selected, setSelected] = useState<Technique>(TECHNIQUES[0])
  const [tacticFilter, setTacticFilter] = useState('All')
  const [copied, setCopied] = useState('')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const filtered = TECHNIQUES.filter(t => tacticFilter === 'All' || t.tactic === tacticFilter)
  const tacticColors: Record<string, string> = {
    'Initial Access': '#ff4444', 'Execution': '#ff6b35', 'Persistence': '#ffd700',
    'Privilege Escalation': '#ff6b35', 'Defense Evasion': '#00ffcc', 'Credential Access': '#ff4444',
    'Discovery': '#00d4ff', 'Lateral Movement': '#ffd700', 'Collection': '#00ffcc',
    'Exfiltration': '#ff4444', 'Command & Control': '#ff6b35', 'Impact': '#ff4444',
  }

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Threat Hunting</h2>
        <p className="section-subheading">MITRE ATT&amp;CK aligned hunting queries, detection logic, and mitigation guidance</p>
      </div>

      {/* ATT&CK tactic selector */}
      <div className="card">
        <div className="card-header"><span className="card-title">Filter by Tactic</span></div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setTacticFilter('All')} className={`tab-btn text-xs ${tacticFilter === 'All' ? 'active' : ''}`}>All Tactics</button>
          {TACTICS.map(t => (
            <button
              key={t}
              onClick={() => setTacticFilter(t)}
              className={`tab-btn text-xs ${tacticFilter === t ? 'active' : ''}`}
              style={tacticFilter === t ? { color: tacticColors[t], borderColor: tacticColors[t] } : {}}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        {/* Technique list */}
        <div className="space-y-2">
          {filtered.map(t => (
            <button
              key={t.id}
              onClick={() => setSelected(t)}
              className="w-full text-left p-3 rounded-lg transition-all"
              style={{
                background: 'rgba(10,20,40,0.6)',
                border: `1px solid ${selected.id === t.id ? 'rgba(0,212,255,0.4)' : 'rgba(0,212,255,0.08)'}`,
              }}
            >
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-xs text-gray-500">{t.id}</span>
                <span className="text-xs font-medium text-gray-200">{t.name}</span>
              </div>
              <span className="text-xs px-1.5 py-0.5 rounded" style={{ background: `rgba(${hexToRgb(tacticColors[t.tactic])}, 0.12)`, color: tacticColors[t.tactic] }}>
                {t.tactic}
              </span>
            </button>
          ))}
        </div>

        {/* Detail panel */}
        <div className="md:col-span-2 space-y-4">
          <div className="card">
            <div className="flex items-start justify-between flex-wrap gap-2 mb-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm text-gray-500">{selected.id}</span>
                  <span className="text-base font-semibold text-gray-200">{selected.name}</span>
                </div>
                <span className="text-xs mt-1 inline-block px-1.5 py-0.5 rounded" style={{ background: `rgba(${hexToRgb(tacticColors[selected.tactic])}, 0.12)`, color: tacticColors[selected.tactic] }}>
                  {selected.tactic}
                </span>
              </div>
              <a
                href={`https://attack.mitre.org/techniques/${selected.id}/`}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-primary text-xs py-1"
              >
                View on ATT&amp;CK ↗
              </a>
            </div>
            <p className="text-sm text-gray-400">{selected.description}</p>
          </div>

          {/* Detection */}
          <div className="card">
            <div className="card-header"><span className="card-title">🔍 Detection Guidance</span></div>
            <ul className="space-y-2">
              {selected.detection.map((d, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                  <span className="text-blue-400 shrink-0 mt-0.5">▸</span> {d}
                </li>
              ))}
            </ul>
            <div className="mt-3 pt-3 border-t" style={{ borderColor: 'rgba(0,212,255,0.1)' }}>
              <div className="text-xs font-semibold text-blue-400 mb-1">Data Sources</div>
              <div className="flex flex-wrap gap-1">
                {selected.dataSource.map(ds => (
                  <span key={ds} className="badge badge-info">{ds}</span>
                ))}
              </div>
            </div>
          </div>

          {/* Hunting query */}
          <div className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="card-title">🎯 Hunting Query (Splunk)</span>
              <button onClick={() => copy(selected.hunting, 'hunt-query')} className="btn-primary text-xs py-1">
                {copied === 'hunt-query' ? '✓ Copied!' : 'Copy Query'}
              </button>
            </div>
            <pre className="code-block text-xs overflow-x-auto whitespace-pre-wrap">{selected.hunting}</pre>
          </div>

          {/* Mitigations */}
          <div className="card">
            <div className="card-header"><span className="card-title">🛡 Mitigations</span></div>
            <ul className="space-y-2">
              {selected.mitigations.map((m, i) => (
                <li key={i} className="flex items-start gap-2 text-sm text-gray-300">
                  <span className="text-green-400 shrink-0 mt-0.5">✓</span> {m}
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>

      {/* ATT&CK Matrix overview */}
      <div className="card">
        <div className="card-header"><span className="card-title">MITRE ATT&amp;CK Coverage Map</span></div>
        <div className="grid grid-cols-3 md:grid-cols-6 lg:grid-cols-12 gap-1 overflow-x-auto">
          {TACTICS.map(tactic => (
            <div key={tactic} className="min-w-[80px]">
              <div className="text-xs font-semibold text-center py-1 mb-1 rounded" style={{ background: `rgba(${hexToRgb(tacticColors[tactic])}, 0.15)`, color: tacticColors[tactic] }}>
                {tactic.split(' ').slice(0, 2).join(' ')}
              </div>
              {TECHNIQUES.filter(t => t.tactic === tactic).map(t => (
                <button
                  key={t.id}
                  onClick={() => { setSelected(t); setTacticFilter('All') }}
                  className="attack-cell w-full text-center mb-1 block"
                  style={selected.id === t.id ? { background: `rgba(${hexToRgb(tacticColors[tactic])}, 0.25)`, borderColor: tacticColors[tactic] } : {}}
                  title={t.name}
                >
                  <div className="text-xs text-gray-400">{t.id}</div>
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Hunting hypotheses */}
      <div className="card">
        <div className="card-header"><span className="card-title">💡 Hunting Hypotheses Generator</span></div>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          {[
            { hyp: 'An attacker is using stolen credentials to access systems outside business hours', tactic: 'Initial Access', steps: ['Query authentication logs for logins between 22:00-06:00', 'Filter by service accounts and privileged users', 'Compare against known user work schedules'] },
            { hyp: 'Malware is maintaining persistence via scheduled tasks or registry keys', tactic: 'Persistence', steps: ['Enumerate all scheduled tasks created in last 7 days', 'Check registry Run keys for unsigned binaries', 'Correlate with new process executions'] },
            { hyp: 'An insider threat is exfiltrating data via cloud storage', tactic: 'Exfiltration', steps: ['Monitor uploads to dropbox.com, drive.google.com, onedrive.com', 'Filter by volume and unusual access times', 'Check DLP alerts for sensitive data keywords'] },
            { hyp: 'Attackers are conducting internal reconnaissance post-compromise', tactic: 'Discovery', steps: ['Look for net.exe, nltest.exe, dsquery.exe usage', 'Monitor LDAP queries with unusual patterns', 'Detect ping sweeps and port scans from internal hosts'] },
          ].map((h, i) => (
            <div key={i} className="p-3 rounded-lg" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.08)' }}>
              <div className="text-xs text-blue-400 mb-1">Hypothesis {i + 1} · {h.tactic}</div>
              <div className="text-sm text-gray-300 mb-2 italic">&ldquo;{h.hyp}&rdquo;</div>
              <div className="text-xs font-semibold text-gray-400 mb-1">Hunting Steps:</div>
              <ol className="space-y-1">
                {h.steps.map((s, si) => (
                  <li key={si} className="text-xs text-gray-400 flex gap-2"><span className="text-blue-400">{si + 1}.</span>{s}</li>
                ))}
              </ol>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function hexToRgb(hex: string): string {
  const r = parseInt(hex.slice(1, 3), 16)
  const g = parseInt(hex.slice(3, 5), 16)
  const b = parseInt(hex.slice(5, 7), 16)
  return `${r},${g},${b}`
}
