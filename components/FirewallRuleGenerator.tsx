'use client'

import React, { useState } from 'react'
import { copyToClipboard, downloadText } from '@/lib/utils'

type Platform = 'iptables' | 'netsh' | 'ufw' | 'pf' | 'cisco' | 'aws' | 'nftables'
type Action = 'block' | 'allow'
type Direction = 'inbound' | 'outbound' | 'both'
type Protocol = 'any' | 'tcp' | 'udp' | 'icmp'
type MainTab = 'ioc' | 'bulk' | 'common' | 'reference'

const PLATFORMS: { id: Platform; label: string; ext: string }[] = [
  { id: 'iptables', label: 'iptables', ext: '.sh' },
  { id: 'netsh', label: 'Windows Firewall (netsh)', ext: '.ps1' },
  { id: 'ufw', label: 'UFW', ext: '.sh' },
  { id: 'pf', label: 'pf (BSD)', ext: '.conf' },
  { id: 'cisco', label: 'Cisco ACL', ext: '.txt' },
  { id: 'aws', label: 'AWS Security Group (CLI)', ext: '.sh' },
  { id: 'nftables', label: 'nftables', ext: '.sh' },
]

interface CommonTemplate {
  id: string
  name: string
  description: string
  ports: number[]
  direction: Direction
  action: Action
}

const COMMON_TEMPLATES: CommonTemplate[] = [
  { id: 'bad-ports', name: 'Block Known Bad Ports', description: 'Block common malware ports used by RATs, backdoors, and exploit frameworks.', ports: [4444, 5555, 6666, 8888, 1337, 31337], direction: 'both', action: 'block' },
  { id: 'c2-ports', name: 'Block Common C2 Ports', description: 'Block ports commonly used by C2 frameworks like Cobalt Strike, Metasploit, and Empire.', ports: [443, 8443, 8080, 50050, 9999, 2222, 4443, 6667], direction: 'outbound', action: 'block' },
  { id: 'tor-exit', name: 'Block Tor Exit Nodes', description: 'Template to block known Tor exit node IPs. Replace placeholder with actual Tor exit node list.', ports: [9001, 9030, 9050, 9051, 9150], direction: 'both', action: 'block' },
  { id: 'smb-external', name: 'Block SMB External', description: 'Prevent SMB traffic from external sources to mitigate lateral movement and ransomware.', ports: [445, 139], direction: 'inbound', action: 'block' },
  { id: 'rdp-external', name: 'Block RDP External', description: 'Block RDP from external networks to prevent brute-force and unauthorized remote access.', ports: [3389], direction: 'inbound', action: 'block' },
  { id: 'dns-nonstandard', name: 'Block DNS over Non-Standard Ports', description: 'Block DNS traffic on non-standard ports to detect DNS tunneling and exfiltration attempts.', ports: [53], direction: 'outbound', action: 'block' },
]

function generateRule(
  platform: Platform,
  target: string,
  action: Action,
  direction: Direction,
  protocol: Protocol,
  port: string,
  comment: string
): string[] {
  const lines: string[] = []
  const dirs: ('inbound' | 'outbound')[] = direction === 'both' ? ['inbound', 'outbound'] : [direction]
  const act = action === 'block' ? 'block' : 'allow'
  const trimmedTarget = target.trim()
  if (!trimmedTarget) return lines

  for (const dir of dirs) {
    switch (platform) {
      case 'iptables': {
        const chain = dir === 'inbound' ? 'INPUT' : 'OUTPUT'
        const addrFlag = dir === 'inbound' ? '-s' : '-d'
        const target_action = action === 'block' ? 'DROP' : 'ACCEPT'
        let cmd = `iptables -A ${chain} ${addrFlag} ${trimmedTarget}`
        if (protocol !== 'any') cmd += ` -p ${protocol}`
        if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` --dport ${port}`
        cmd += ` -j ${target_action}`
        if (comment) cmd += ` -m comment --comment "${comment}"`
        lines.push(cmd)
        break
      }
      case 'netsh': {
        const dirStr = dir === 'inbound' ? 'in' : 'out'
        const actStr = action === 'block' ? 'block' : 'allow'
        const name = comment || `${act}-${trimmedTarget}`
        let cmd = `netsh advfirewall firewall add rule name="${name}" dir=${dirStr} action=${actStr} remoteip=${trimmedTarget}`
        if (protocol !== 'any') cmd += ` protocol=${protocol}`
        if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` localport=${port}`
        lines.push(cmd)
        break
      }
      case 'ufw': {
        const actStr = action === 'block' ? 'deny' : 'allow'
        let cmd: string
        if (dir === 'inbound') {
          cmd = `ufw ${actStr} from ${trimmedTarget} to any`
          if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` port ${port} proto ${protocol}`
        } else {
          cmd = `ufw ${actStr} out to ${trimmedTarget}`
          if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` port ${port} proto ${protocol}`
        }
        if (comment) cmd += ` comment "${comment}"`
        lines.push(cmd)
        break
      }
      case 'pf': {
        const actStr = action === 'block' ? 'block' : 'pass'
        const dirStr = dir === 'inbound' ? 'in' : 'out'
        const addrPart = dir === 'inbound' ? `from ${trimmedTarget} to any` : `from any to ${trimmedTarget}`
        let cmd = `${actStr} ${dirStr} quick`
        if (protocol !== 'any') cmd += ` proto ${protocol}`
        cmd += ` ${addrPart}`
        if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` port ${port}`
        lines.push(cmd)
        break
      }
      case 'cisco': {
        const actStr = action === 'block' ? 'deny' : 'permit'
        const proto = protocol === 'any' ? 'ip' : protocol
        const src = dir === 'inbound' ? `host ${trimmedTarget}` : 'any'
        const dst = dir === 'inbound' ? 'any' : `host ${trimmedTarget}`
        let cmd = `access-list 100 ${actStr} ${proto} ${src} ${dst}`
        if (port && proto !== 'ip' && proto !== 'icmp') cmd += ` eq ${port}`
        lines.push(cmd)
        break
      }
      case 'aws': {
        const cidr = trimmedTarget.includes('/') ? trimmedTarget : `${trimmedTarget}/32`
        const proto = protocol === 'any' ? '-1' : protocol
        const portPart = port ? port : '0-65535'
        if (action === 'block') {
          const dirCmd = dir === 'inbound' ? 'revoke-security-group-ingress' : 'revoke-security-group-egress'
          lines.push(`aws ec2 ${dirCmd} --group-id sg-XXXXX --protocol ${proto} --port ${portPart} --cidr ${cidr}`)
        } else {
          const dirCmd = dir === 'inbound' ? 'authorize-security-group-ingress' : 'authorize-security-group-egress'
          lines.push(`aws ec2 ${dirCmd} --group-id sg-XXXXX --protocol ${proto} --port ${portPart} --cidr ${cidr}`)
        }
        break
      }
      case 'nftables': {
        const chain = dir === 'inbound' ? 'input' : 'output'
        const addrKey = dir === 'inbound' ? 'saddr' : 'daddr'
        const target_action = action === 'block' ? 'drop' : 'accept'
        let cmd = `nft add rule ip filter ${chain}`
        if (protocol !== 'any') cmd += ` ip protocol ${protocol}`
        cmd += ` ip ${addrKey} ${trimmedTarget}`
        if (port && protocol !== 'any' && protocol !== 'icmp') cmd += ` ${protocol} dport ${port}`
        cmd += ` ${target_action}`
        if (comment) cmd += ` comment "${comment}"`
        lines.push(cmd)
        break
      }
    }
  }
  return lines
}

function generatePortRules(platform: Platform, ports: number[], direction: Direction, action: Action): string[] {
  const lines: string[] = []
  const dirs: ('inbound' | 'outbound')[] = direction === 'both' ? ['inbound', 'outbound'] : [direction]

  for (const port of ports) {
    for (const dir of dirs) {
      const rules = generateRule(platform, '0.0.0.0/0', action, dir, 'tcp', String(port), `Block port ${port}`)
      lines.push(...rules)
    }
  }
  return lines
}

const REFERENCE_DATA: { platform: Platform; syntax: string; tips: string; example: string }[] = [
  { platform: 'iptables', syntax: 'iptables -A <CHAIN> -s <IP> -p <proto> --dport <port> -j <ACTION>', tips: 'Rules are evaluated top-to-bottom; order matters. Use -I to insert at top. Use iptables-save to persist rules across reboots.', example: 'iptables -A INPUT -s 192.168.1.100 -p tcp --dport 22 -j DROP -m comment --comment "Block SSH from host"' },
  { platform: 'netsh', syntax: 'netsh advfirewall firewall add rule name="<NAME>" dir=<in|out> action=<allow|block> remoteip=<IP>', tips: 'Run as Administrator. Use "show rule name=all" to list rules. Rule names must be unique or use "delete rule" to remove duplicates.', example: 'netsh advfirewall firewall add rule name="Block Attacker" dir=in action=block remoteip=10.0.0.50 protocol=tcp localport=443' },
  { platform: 'ufw', syntax: 'ufw <allow|deny> from <IP> to any [port <PORT> proto <PROTO>]', tips: 'Enable with "ufw enable". Use "ufw status numbered" to see rule order. Delete rules by number with "ufw delete <NUM>".', example: 'ufw deny from 203.0.113.0/24 to any port 22 proto tcp' },
  { platform: 'pf', syntax: '<pass|block> <in|out> quick [proto <PROTO>] from <SRC> to <DST> [port <PORT>]', tips: 'Use "pfctl -f /etc/pf.conf" to reload. The "quick" keyword stops rule evaluation on match. Test with "pfctl -nf" first.', example: 'block in quick proto tcp from 10.0.0.0/8 to any port 3389' },
  { platform: 'cisco', syntax: 'access-list <NUM> <permit|deny> <proto> <src> <dst> [eq <port>]', tips: 'Apply ACLs to interfaces with "ip access-group". Standard ACLs (1-99) filter by source only. Extended ACLs (100-199) filter by src/dst/port.', example: 'access-list 100 deny tcp host 192.168.1.100 any eq 445' },
  { platform: 'aws', syntax: 'aws ec2 <authorize|revoke>-security-group-<ingress|egress> --group-id <SG> --protocol <PROTO> --port <PORT> --cidr <CIDR>', tips: 'Security Groups are stateful. Use NACLs for stateless rules. Remember to specify the correct --group-id for your VPC.', example: 'aws ec2 revoke-security-group-ingress --group-id sg-0123456789 --protocol tcp --port 22 --cidr 0.0.0.0/0' },
  { platform: 'nftables', syntax: 'nft add rule ip filter <chain> ip <saddr|daddr> <IP> <drop|accept>', tips: 'Successor to iptables. Use "nft list ruleset" to view all rules. Create tables/chains before adding rules.', example: 'nft add rule ip filter input ip saddr 10.0.0.50 tcp dport 443 drop comment "Block C2"' },
]

export default function FirewallRuleGenerator() {
  const [activeTab, setActiveTab] = useState<MainTab>('ioc')
  const [platform, setPlatform] = useState<Platform>('iptables')
  const [action, setAction] = useState<Action>('block')
  const [direction, setDirection] = useState<Direction>('inbound')
  const [protocol, setProtocol] = useState<Protocol>('any')
  const [port, setPort] = useState('')
  const [comment, setComment] = useState('')
  const [iocInput, setIocInput] = useState('')
  const [generatedRules, setGeneratedRules] = useState('')
  const [copied, setCopied] = useState('')

  // Bulk tab state
  const [bulkInput, setBulkInput] = useState('')
  const [bulkPlatform, setBulkPlatform] = useState<Platform>('iptables')
  const [bulkRules, setBulkRules] = useState('')
  const [bulkCount, setBulkCount] = useState(0)

  // Common tab state
  const [commonPlatform, setCommonPlatform] = useState<Platform>('iptables')
  const [commonResults, setCommonResults] = useState<Record<string, string>>({})

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const handleGenerate = () => {
    const lines = iocInput.split('\n').filter(l => l.trim())
    const rules: string[] = []
    for (const line of lines) {
      rules.push(...generateRule(platform, line, action, direction, protocol, port, comment))
    }
    setGeneratedRules(rules.join('\n'))
  }

  const handleBulkGenerate = () => {
    const lines = bulkInput.split('\n').filter(l => l.trim())
    const rules: string[] = []
    for (const line of lines) {
      rules.push(...generateRule(bulkPlatform, line, action, direction, protocol, port, comment))
    }
    setBulkRules(rules.join('\n'))
    setBulkCount(rules.length)
  }

  const handleBulkDownload = () => {
    const ext = PLATFORMS.find(p => p.id === bulkPlatform)?.ext || '.txt'
    const filename = `firewall-rules${ext}`
    let content = bulkRules
    if (ext === '.sh') {
      content = `#!/bin/bash\nset -euo pipefail\n# Generated firewall rules - ${new Date().toISOString()}\n\n${bulkRules}`
    } else if (ext === '.ps1') {
      content = `# Generated firewall rules - ${new Date().toISOString()}\n\n${bulkRules}`
    }
    downloadText(content, filename)
  }

  const handleCommonGenerate = (template: CommonTemplate) => {
    const rules = generatePortRules(commonPlatform, template.ports, template.direction, template.action)
    setCommonResults(prev => ({ ...prev, [template.id]: rules.join('\n') }))
  }

  const TABS: { id: MainTab; label: string }[] = [
    { id: 'ioc', label: '🛡 IOC to Firewall Rules' },
    { id: 'bulk', label: '📋 Bulk Rule Generator' },
    { id: 'common', label: '🔒 Common Block Rules' },
    { id: 'reference', label: '📖 Rule Reference' },
  ]

  const renderPlatformSelector = (value: Platform, onChange: (p: Platform) => void) => (
    <div className="flex flex-wrap gap-1.5">
      {PLATFORMS.map(p => (
        <button
          key={p.id}
          onClick={() => onChange(p.id)}
          className={`tab-btn ${value === p.id ? 'active' : ''}`}
        >
          {p.label}
        </button>
      ))}
    </div>
  )

  const renderConfigPanel = () => (
    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-3">
      <div>
        <label className="text-xs text-gray-400 mb-1 block">Action</label>
        <select className="cyber-input" value={action} onChange={e => setAction(e.target.value as Action)}>
          <option value="block">Block / Deny</option>
          <option value="allow">Allow</option>
        </select>
      </div>
      <div>
        <label className="text-xs text-gray-400 mb-1 block">Direction</label>
        <select className="cyber-input" value={direction} onChange={e => setDirection(e.target.value as Direction)}>
          <option value="inbound">Inbound</option>
          <option value="outbound">Outbound</option>
          <option value="both">Both</option>
        </select>
      </div>
      <div>
        <label className="text-xs text-gray-400 mb-1 block">Protocol</label>
        <select className="cyber-input" value={protocol} onChange={e => setProtocol(e.target.value as Protocol)}>
          <option value="any">Any</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>
      </div>
      <div>
        <label className="text-xs text-gray-400 mb-1 block">Port (optional)</label>
        <input
          className="cyber-input"
          value={port}
          onChange={e => setPort(e.target.value)}
          placeholder="e.g. 443"
        />
      </div>
      <div className="col-span-2 md:col-span-4">
        <label className="text-xs text-gray-400 mb-1 block">Rule Comment / Description</label>
        <input
          className="cyber-input"
          value={comment}
          onChange={e => setComment(e.target.value)}
          placeholder="e.g. Block malicious IP from threat intel"
        />
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="card">
        <h1 className="card-title text-lg">🔥 Firewall Rule Generator</h1>
        <p className="text-xs text-gray-400 mt-1">
          Generate firewall rules for multiple platforms from IOCs, bulk IP lists, or common security templates.
        </p>
      </div>

      {/* Tab Navigation */}
      <div className="flex flex-wrap gap-2">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            className={`tab-btn ${activeTab === t.id ? 'active' : ''}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab 1: IOC to Firewall Rules */}
      {activeTab === 'ioc' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">IOC Input</span>
              <button onClick={() => setIocInput('')} className="ml-auto text-xs text-gray-500 hover:text-red-400">Clear</button>
            </div>
            <textarea
              className="cyber-textarea w-full h-32 mt-2"
              value={iocInput}
              onChange={e => setIocInput(e.target.value)}
              placeholder="Paste IOCs here - one per line&#10;192.168.1.100&#10;10.0.0.0/24&#10;malicious-domain.com&#10;203.0.113.50"
            />
          </div>

          <div className="card">
            <span className="section-heading">Platform</span>
            {renderPlatformSelector(platform, setPlatform)}
            {renderConfigPanel()}
            <div className="mt-4">
              <button
                onClick={handleGenerate}
                disabled={!iocInput.trim()}
                className="btn-primary disabled:opacity-50"
              >
                🔧 Generate Rules
              </button>
            </div>
          </div>

          {generatedRules && (
            <div className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="card-title">Generated Rules</span>
                <div className="flex gap-2">
                  <span className="badge badge-info text-xs">{generatedRules.split('\n').length} rules</span>
                  <button onClick={() => copy(generatedRules, 'ioc-rules')} className="btn-primary text-xs py-1">
                    {copied === 'ioc-rules' ? '✓ Copied!' : 'Copy Rules'}
                  </button>
                </div>
              </div>
              <pre className="code-block text-xs whitespace-pre-wrap break-all">{generatedRules}</pre>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Bulk Rule Generator */}
      {activeTab === 'bulk' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header">
              <span className="card-title">Bulk IP / CIDR Input</span>
              <button onClick={() => { setBulkInput(''); setBulkRules(''); setBulkCount(0) }} className="ml-auto text-xs text-gray-500 hover:text-red-400">Clear</button>
            </div>
            <textarea
              className="cyber-textarea w-full h-40 mt-2"
              value={bulkInput}
              onChange={e => setBulkInput(e.target.value)}
              placeholder="Paste IPs or CIDRs here - one per line&#10;192.168.1.100&#10;10.0.0.0/8&#10;172.16.0.0/12&#10;203.0.113.0/24"
            />
          </div>

          <div className="card">
            <span className="section-heading">Platform</span>
            {renderPlatformSelector(bulkPlatform, setBulkPlatform)}
            {renderConfigPanel()}
            <div className="mt-4 flex gap-2">
              <button
                onClick={handleBulkGenerate}
                disabled={!bulkInput.trim()}
                className="btn-primary disabled:opacity-50"
              >
                🔧 Generate All Rules
              </button>
            </div>
          </div>

          {bulkRules && (
            <div className="card">
              <div className="flex items-center justify-between mb-2">
                <span className="card-title">Generated Rules</span>
                <div className="flex gap-2 items-center">
                  <span className="badge badge-info text-xs">{bulkCount} rules generated</span>
                  <button onClick={() => copy(bulkRules, 'bulk-rules')} className="btn-primary text-xs py-1">
                    {copied === 'bulk-rules' ? '✓ Copied!' : 'Copy All Rules'}
                  </button>
                  <button onClick={handleBulkDownload} className="btn-primary text-xs py-1">
                    ⬇ Download as Script
                  </button>
                </div>
              </div>
              <pre className="code-block text-xs whitespace-pre-wrap break-all">{bulkRules}</pre>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Common Block Rules */}
      {activeTab === 'common' && (
        <div className="space-y-4">
          <div className="card">
            <span className="section-heading">Platform for Templates</span>
            {renderPlatformSelector(commonPlatform, setCommonPlatform)}
          </div>

          {COMMON_TEMPLATES.map(template => (
            <div key={template.id} className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
              <div className="flex items-start justify-between mb-2">
                <div>
                  <span className="section-heading">{template.name}</span>
                  <p className="text-xs text-gray-400 mt-1">{template.description}</p>
                  <div className="flex flex-wrap gap-1 mt-2">
                    {template.ports.map(p => (
                      <span key={p} className="badge badge-info text-xs">Port {p}</span>
                    ))}
                    <span className="badge badge-critical text-xs">{template.direction}</span>
                  </div>
                </div>
                <button onClick={() => handleCommonGenerate(template)} className="btn-primary text-xs py-1 whitespace-nowrap">
                  Generate
                </button>
              </div>
              {commonResults[template.id] && (
                <div className="mt-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="section-subheading">Generated Rules</span>
                    <button onClick={() => copy(commonResults[template.id], `common-${template.id}`)} className="btn-primary text-xs py-1">
                      {copied === `common-${template.id}` ? '✓ Copied!' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block text-xs whitespace-pre-wrap break-all">{commonResults[template.id]}</pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Tab 4: Rule Reference / Cheat Sheet */}
      {activeTab === 'reference' && (
        <div className="space-y-4">
          <div className="card">
            <span className="card-title">📖 Firewall Rule Quick Reference</span>
            <p className="text-xs text-gray-400 mt-1">Syntax reference, examples, and tips for each firewall platform.</p>
          </div>

          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <span className="section-heading">Syntax Reference</span>
            <div className="overflow-x-auto mt-3">
              <table className="cyber-table w-full">
                <thead>
                  <tr>
                    <th>Platform</th>
                    <th>Base Syntax</th>
                    <th>Tips</th>
                  </tr>
                </thead>
                <tbody>
                  {REFERENCE_DATA.map(r => (
                    <tr key={r.platform}>
                      <td className="font-semibold text-blue-400 whitespace-nowrap">{PLATFORMS.find(p => p.id === r.platform)?.label}</td>
                      <td><code className="text-xs font-mono text-gray-300">{r.syntax}</code></td>
                      <td className="text-xs text-gray-400">{r.tips}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <span className="section-heading">Example Rules by Platform</span>
            <div className="space-y-3 mt-3">
              {REFERENCE_DATA.map(r => (
                <div key={r.platform}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="section-subheading">{PLATFORMS.find(p => p.id === r.platform)?.label}</span>
                    <button onClick={() => copy(r.example, `ref-${r.platform}`)} className="btn-primary text-xs py-1">
                      {copied === `ref-${r.platform}` ? '✓' : 'Copy'}
                    </button>
                  </div>
                  <pre className="code-block text-xs whitespace-pre-wrap break-all">{r.example}</pre>
                </div>
              ))}
            </div>
          </div>

          <div className="card" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
            <span className="section-heading">⚠ Common Mistakes &amp; Tips</span>
            <div className="overflow-x-auto mt-3">
              <table className="cyber-table w-full">
                <thead>
                  <tr>
                    <th>Mistake</th>
                    <th>Why It&apos;s Wrong</th>
                    <th>Fix</th>
                  </tr>
                </thead>
                <tbody>
                  <tr>
                    <td className="text-red-400 text-xs">Placing ALLOW before DENY in iptables</td>
                    <td className="text-xs text-gray-400">First matching rule wins; ALLOW will take precedence</td>
                    <td className="text-xs text-green-400">Use -I to insert DENY rules at the top of the chain</td>
                  </tr>
                  <tr>
                    <td className="text-red-400 text-xs">Not persisting iptables rules</td>
                    <td className="text-xs text-gray-400">Rules are lost on reboot without saving</td>
                    <td className="text-xs text-green-400">Run iptables-save &gt; /etc/iptables/rules.v4</td>
                  </tr>
                  <tr>
                    <td className="text-red-400 text-xs">Forgetting to enable UFW after adding rules</td>
                    <td className="text-xs text-gray-400">Rules exist but firewall is inactive</td>
                    <td className="text-xs text-green-400">Run &quot;ufw enable&quot; after configuring rules</td>
                  </tr>
                  <tr>
                    <td className="text-red-400 text-xs">Using standard ACL when extended is needed</td>
                    <td className="text-xs text-gray-400">Standard ACLs (1-99) only filter by source IP</td>
                    <td className="text-xs text-green-400">Use extended ACLs (100-199) for port/protocol filtering</td>
                  </tr>
                  <tr>
                    <td className="text-red-400 text-xs">Not specifying /32 for single IPs in AWS</td>
                    <td className="text-xs text-gray-400">CIDR notation is required; bare IP is invalid</td>
                    <td className="text-xs text-green-400">Always append /32 for individual host IPs</td>
                  </tr>
                  <tr>
                    <td className="text-red-400 text-xs">Missing &quot;quick&quot; keyword in pf rules</td>
                    <td className="text-xs text-gray-400">Without quick, pf evaluates all rules and uses the last match</td>
                    <td className="text-xs text-green-400">Add &quot;quick&quot; to stop on first match for block rules</td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
