'use client'

import React, { useState } from 'react'
import Navigation, { type Section } from '@/components/Navigation'
import Dashboard from '@/components/Dashboard'
import ThreatIntelligence from '@/components/ThreatIntelligence'
import IOCManager from '@/components/IOCManager'
import IncidentResponse from '@/components/IncidentResponse'
import ThreatHunting from '@/components/ThreatHunting'
import SIEMQueryBuilder from '@/components/SIEMQueryBuilder'
import VulnerabilityManagement from '@/components/VulnerabilityManagement'
import LogAnalysis from '@/components/LogAnalysis'
import NetworkAnalysis from '@/components/NetworkAnalysis'
import SecurityChecklists from '@/components/SecurityChecklists'
import EncodeDecode from '@/components/EncodeDecode'
import ReportGenerator from '@/components/ReportGenerator'
import Settings from '@/components/Settings'

export default function Home() {
  const [activeSection, setActiveSection] = useState<Section>('dashboard')
  const [sidebarOpen, setSidebarOpen] = useState(true)

  const navigate = (section: string) => {
    setActiveSection(section as Section)
    // Scroll to top on mobile
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return (
    <div className="flex min-h-screen">
      <Navigation
        active={activeSection}
        onNavigate={navigate}
        sidebarOpen={sidebarOpen}
        onToggle={() => setSidebarOpen(o => !o)}
      />

      {/* Main content */}
      <main
        className="flex-1 overflow-auto"
        style={{
          marginLeft: sidebarOpen ? 0 : 0,
          minHeight: '100vh',
          background: 'var(--dark-900)',
        }}
      >
        {/* Top bar */}
        <header className="sticky top-0 z-20 px-6 py-3 flex items-center gap-4" style={{ background: 'rgba(5,10,21,0.95)', borderBottom: '1px solid rgba(0,212,255,0.08)', backdropFilter: 'blur(10px)' }}>
          {/* Desktop sidebar toggle */}
          <button
            onClick={() => setSidebarOpen(o => !o)}
            className="hidden md:flex w-7 h-7 rounded items-center justify-center text-blue-400 text-sm transition-colors hover:bg-blue-500/10"
            style={{ border: '1px solid rgba(0,212,255,0.15)' }}
            aria-label="Toggle sidebar"
          >
            {sidebarOpen ? '‹' : '›'}
          </button>

          <div className="flex items-center gap-2 text-xs text-gray-500">
            <span className="text-blue-400">🛡</span>
            <span className="hidden sm:inline">Blue Team Cyber Dashboard</span>
            <span className="text-gray-700">/</span>
            <span className="text-blue-400 capitalize">{activeSection.replace(/-/g, ' ')}</span>
          </div>

          <div className="ml-auto flex items-center gap-3">
            <div className="flex items-center gap-1.5">
              <span className="pulse-dot" />
              <span className="text-xs text-gray-500 hidden sm:inline">Systems Active</span>
            </div>
          </div>
        </header>

        {/* Content */}
        <div className="p-4 md:p-6 max-w-7xl mx-auto">
          {activeSection === 'dashboard' && <Dashboard onNavigate={navigate} />}
          {activeSection === 'threat-intel' && <ThreatIntelligence onNavigate={navigate} />}
          {activeSection === 'ioc-manager' && <IOCManager />}
          {activeSection === 'incident-response' && <IncidentResponse />}
          {activeSection === 'threat-hunting' && <ThreatHunting />}
          {activeSection === 'siem-queries' && <SIEMQueryBuilder />}
          {activeSection === 'vulnerability' && <VulnerabilityManagement />}
          {activeSection === 'log-analysis' && <LogAnalysis />}
          {activeSection === 'network-analysis' && <NetworkAnalysis />}
          {activeSection === 'checklists' && <SecurityChecklists />}
          {activeSection === 'encode-decode' && <EncodeDecode />}
          {activeSection === 'report-generator' && <ReportGenerator />}
          {activeSection === 'settings' && <Settings />}
        </div>
      </main>
    </div>
  )
}
