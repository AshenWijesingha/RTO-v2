'use client'

import React from 'react'

export type Section =
  | 'dashboard'
  | 'threat-intel'
  | 'ioc-manager'
  | 'incident-response'
  | 'threat-hunting'
  | 'siem-queries'
  | 'nmap-builder'
  | 'vulnerability'
  | 'log-analysis'
  | 'network-analysis'
  | 'checklists'
  | 'encode-decode'
  | 'report-generator'
  | 'phishing-analyzer'
  | 'firewall-rules'
  | 'reverse-shells'
  | 'password-tools'
  | 'regex-tester'
  | 'settings'

interface NavItem {
  id: Section
  label: string
  icon: string
  color?: string
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: '⬡', color: '#00d4ff' },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: '🔍', color: '#ff4444' },
  { id: 'ioc-manager', label: 'IOC Manager', icon: '📌', color: '#ff6b35' },
  { id: 'incident-response', label: 'Incident Response', icon: '🚨', color: '#ffd700' },
  { id: 'threat-hunting', label: 'Threat Hunting', icon: '🎯', color: '#00ffcc' },
  { id: 'siem-queries', label: 'SIEM Query Builder', icon: '⚡', color: '#00d4ff' },
  { id: 'nmap-builder', label: 'NMAP Query Builder', icon: '🔭', color: '#39ff14' },
  { id: 'vulnerability', label: 'Vulnerability Mgmt', icon: '🛡', color: '#ff6b35' },
  { id: 'log-analysis', label: 'Log Analysis', icon: '📋', color: '#00ffcc' },
  { id: 'network-analysis', label: 'Network Analysis', icon: '🌐', color: '#00d4ff' },
  { id: 'phishing-analyzer', label: 'Phishing Analyzer', icon: '📧', color: '#ff4444' },
  { id: 'firewall-rules', label: 'Firewall Rules', icon: '🔥', color: '#ffd700' },
  { id: 'reverse-shells', label: 'Reverse Shells', icon: '💀', color: '#ff0055' },
  { id: 'password-tools', label: 'Password & Hash', icon: '🔐', color: '#a855f7' },
  { id: 'regex-tester', label: 'Regex Tester', icon: '🔣', color: '#00ffcc' },
  { id: 'checklists', label: 'Security Checklists', icon: '✓', color: '#39ff14' },
  { id: 'encode-decode', label: 'Encode / Decode', icon: '⚙', color: '#a0b3c8' },
  { id: 'report-generator', label: 'Report Generator', icon: '📄', color: '#00d4ff' },
  { id: 'settings', label: 'API Settings', icon: '🔑', color: '#a0b3c8' },
]

interface Props {
  active: Section
  onNavigate: (s: Section) => void
  sidebarOpen: boolean
  onToggle: () => void
}

export default function Navigation({ active, onNavigate, sidebarOpen, onToggle }: Props) {
  return (
    <>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-30 md:hidden"
          onClick={onToggle}
        />
      )}

      {/* Sidebar */}
      <aside
        className={`sidebar fixed top-0 left-0 flex flex-col ${sidebarOpen ? '' : 'sidebar-collapsed'} md:relative md:translate-x-0`}
      >
        {/* Header */}
        <div className="p-4 border-b border-blue-900/30">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg flex items-center justify-center text-lg"
              style={{ background: 'rgba(0,212,255,0.15)', border: '1px solid rgba(0,212,255,0.3)' }}>
              🛡
            </div>
            <div>
              <div className="matrix-header text-xs font-bold text-blue-400">SECURITY OPS</div>
              <div className="text-xs text-gray-500">Cyber Dashboard v2</div>
            </div>
          </div>
        </div>

        {/* Nav items */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-0.5">
          {NAV_ITEMS.map(item => (
            <button
              key={item.id}
              onClick={() => { onNavigate(item.id); if (window.innerWidth < 768) onToggle() }}
              className={`nav-item w-full text-left ${active === item.id ? 'active' : ''}`}
            >
              <span className="text-base w-5 text-center">{item.icon}</span>
              <span className="truncate">{item.label}</span>
            </button>
          ))}
        </nav>

        {/* Footer */}
        <div className="p-3 border-t border-blue-900/20">
          <div className="text-xs text-gray-600 text-center">
            For authorized security operations only
          </div>
        </div>
      </aside>

      {/* Mobile toggle button */}
      <button
        onClick={onToggle}
        className="md:hidden fixed top-4 left-4 z-50 w-8 h-8 rounded-lg flex items-center justify-center text-blue-400"
        style={{ background: 'rgba(5,10,21,0.95)', border: '1px solid rgba(0,212,255,0.3)' }}
        aria-label="Toggle menu"
      >
        {sidebarOpen ? '✕' : '☰'}
      </button>
    </>
  )
}
