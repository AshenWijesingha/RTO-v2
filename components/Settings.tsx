'use client'

import React, { useState, useEffect } from 'react'
import { lsGet, lsSet } from '@/lib/utils'

interface ApiKeys {
  abuseipdb: string
  virustotal: string
  shodan: string
  otx: string
  greynoise: string
}

export default function Settings() {
  const [keys, setKeys] = useState<ApiKeys>({ abuseipdb: '', virustotal: '', shodan: '', otx: '', greynoise: '' })
  const [saved, setSaved] = useState(false)
  const [notes, setNotes] = useState('')

  useEffect(() => {
    setKeys(lsGet<ApiKeys>('bt_apikeys', { abuseipdb: '', virustotal: '', shodan: '', otx: '', greynoise: '' }))
    setNotes(lsGet<string>('bt_analyst_notes', ''))
  }, [])

  const saveKeys = () => {
    lsSet('bt_apikeys', keys)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const saveNotes = () => {
    lsSet('bt_analyst_notes', notes)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const clearAll = () => {
    if (confirm('Clear ALL stored data? This will remove IOCs, incidents, API keys, and settings.')) {
      localStorage.clear()
      setKeys({ abuseipdb: '', virustotal: '', shodan: '', otx: '', greynoise: '' })
      setNotes('')
    }
  }

  const apiConfigs = [
    {
      key: 'abuseipdb' as const,
      name: 'AbuseIPDB',
      url: 'https://www.abuseipdb.com/api',
      desc: 'IP abuse confidence scoring and reputation. Free tier: 1,000 checks/day',
      features: ['IP reputation check', 'Abuse confidence score', 'Report history'],
    },
    {
      key: 'virustotal' as const,
      name: 'VirusTotal',
      url: 'https://www.virustotal.com/gui/my-apikey',
      desc: 'Multi-engine file, URL, domain, and IP analysis. Free tier: 4 lookups/min',
      features: ['File hash analysis', 'URL scanning', 'Domain reputation', 'IP analysis'],
    },
    {
      key: 'shodan' as const,
      name: 'Shodan',
      url: 'https://account.shodan.io/',
      desc: 'Internet device search engine. Free account with limited queries.',
      features: ['Host information', 'Open ports', 'Banner grabbing', 'Vulnerability data'],
    },
    {
      key: 'otx' as const,
      name: 'AlienVault OTX',
      url: 'https://otx.alienvault.com/api',
      desc: 'Open threat intelligence platform. Completely free.',
      features: ['Threat intelligence', 'IOC enrichment', 'Pulse subscriptions'],
    },
    {
      key: 'greynoise' as const,
      name: 'GreyNoise',
      url: 'https://viz.greynoise.io/account/api-key',
      desc: 'Internet scanner and noise classification. Free community tier available.',
      features: ['IP noise classification', 'Scanner identification', 'Benign/malicious differentiation'],
    },
  ]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">API Settings</h2>
        <p className="section-subheading">Configure API keys for threat intelligence integrations</p>
      </div>

      {/* Security notice */}
      <div className="alert-info">
        <span>🔒</span>
        <div className="text-sm text-blue-200">
          <strong>Privacy:</strong> All API keys are stored locally in your browser (localStorage) and are never sent to any server other than the respective API provider. This dashboard has no backend.
        </div>
      </div>

      {/* API Key configuration */}
      <div className="space-y-4">
        {apiConfigs.map(config => (
          <div key={config.key} className="card">
            <div className="flex items-start justify-between flex-wrap gap-3 mb-3">
              <div>
                <div className="text-sm font-semibold text-blue-400">{config.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">{config.desc}</div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {config.features.map(f => <span key={f} className="badge badge-info">{f}</span>)}
                </div>
              </div>
              <a href={config.url} target="_blank" rel="noopener noreferrer" className="btn-primary text-xs py-1 whitespace-nowrap">
                Get API Key ↗
              </a>
            </div>
            <div className="flex gap-2">
              <input
                id={`show-${config.key}`}
                type="password"
                className="cyber-input flex-1"
                value={keys[config.key]}
                onChange={e => setKeys(k => ({ ...k, [config.key]: e.target.value }))}
                placeholder={`Enter ${config.name} API key...`}
              />
              <button
                onClick={() => { const show = document.getElementById(`show-${config.key}`) as HTMLInputElement; if (show) show.type = show.type === 'password' ? 'text' : 'password' }}
                className="btn-primary text-xs"
              >
                👁
              </button>
            </div>
            {keys[config.key] && (
              <div className="flex items-center gap-1 mt-1.5">
                <span className="pulse-dot" style={{ width: 6, height: 6, background: '#39ff14' }}></span>
                <span className="text-xs" style={{ color: '#39ff14' }}>Key configured</span>
              </div>
            )}
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <button onClick={saveKeys} className="btn-success">
          {saved ? '✓ Saved!' : 'Save API Keys'}
        </button>
      </div>

      {/* Analyst notes */}
      <div className="card">
        <div className="card-header"><span className="card-title">📝 Analyst Notes (Persistent)</span></div>
        <textarea
          className="cyber-textarea w-full h-40"
          value={notes}
          onChange={e => setNotes(e.target.value)}
          placeholder="Use this space for temporary analysis notes, commands, or observations..."
        />
        <div className="flex gap-2 mt-3">
          <button onClick={saveNotes} className="btn-success">Save Notes</button>
          <button onClick={() => setNotes('')} className="btn-danger">Clear Notes</button>
        </div>
      </div>

      {/* Free resources */}
      <div className="card">
        <div className="card-header"><span className="card-title">Free APIs (No Key Required)</span></div>
        <div className="space-y-2">
          {[
            { name: 'ip-api.com', use: 'IP geolocation and ASN info', url: 'https://ip-api.com' },
            { name: 'MalwareBazaar', use: 'File hash malware lookup', url: 'https://bazaar.abuse.ch' },
            { name: 'URLhaus', use: 'Malicious URL database', url: 'https://urlhaus.abuse.ch' },
            { name: 'NIST NVD', use: 'CVE vulnerability database', url: 'https://nvd.nist.gov' },
            { name: 'RDAP', use: 'Domain WHOIS information', url: 'https://rdap.org' },
            { name: 'Google DNS', use: 'DNS record lookup', url: 'https://dns.google' },
          ].map(api => (
            <div key={api.name} className="flex items-center gap-3 p-2 rounded" style={{ background: 'rgba(57,255,20,0.04)', border: '1px solid rgba(57,255,20,0.12)' }}>
              <span className="pulse-dot" style={{ width: 6, height: 6, background: '#39ff14' }} />
              <div className="flex-1">
                <span className="text-xs font-semibold text-green-400">{api.name}</span>
                <span className="text-xs text-gray-500 ml-2">{api.use}</span>
              </div>
              <a href={api.url} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline">↗</a>
            </div>
          ))}
        </div>
      </div>

      {/* Data management */}
      <div className="card">
        <div className="card-header"><span className="card-title">Data Management</span></div>
        <p className="text-xs text-gray-500 mb-4">All data is stored locally in your browser. Nothing is sent to external servers except direct API calls.</p>
        <button onClick={clearAll} className="btn-danger">⚠ Clear All Local Data</button>
      </div>
    </div>
  )
}
