'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { lsGet, lsSet, detectIOCType, defang, copyToClipboard, downloadJSON, toCSV, downloadText, now, formatDate } from '@/lib/utils'

export interface IOC {
  id: string
  value: string
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  status: 'Active' | 'Resolved' | 'False Positive' | 'Under Investigation'
  source: string
  notes: string
  tags: string[]
  timestamp: string
  lastSeen: string
}

const SEVERITIES = ['Critical', 'High', 'Medium', 'Low', 'Info'] as const
const STATUSES = ['Active', 'Under Investigation', 'Resolved', 'False Positive'] as const

export default function IOCManager() {
  const [iocs, setIocs] = useState<IOC[]>([])
  const [filter, setFilter] = useState('')
  const [filterType, setFilterType] = useState('All')
  const [filterSev, setFilterSev] = useState('All')
  const [filterStatus, setFilterStatus] = useState('All')
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [copied, setCopied] = useState('')
  const [bulkInput, setBulkInput] = useState('')
  const [showBulk, setShowBulk] = useState(false)
  const [form, setForm] = useState<Partial<IOC>>({
    value: '', type: 'Unknown', severity: 'Medium', status: 'Active',
    source: '', notes: '', tags: [],
  })
  const [tagInput, setTagInput] = useState('')

  useEffect(() => {
    setIocs(lsGet<IOC[]>('bt_iocs', []))
  }, [])

  const save = useCallback((updated: IOC[]) => {
    setIocs(updated)
    lsSet('bt_iocs', updated)
  }, [])

  const openNew = () => {
    setForm({ value: '', type: 'Unknown', severity: 'Medium', status: 'Active', source: '', notes: '', tags: [] })
    setTagInput('')
    setEditId(null)
    setShowForm(true)
  }

  const openEdit = (ioc: IOC) => {
    setForm({ ...ioc })
    setTagInput(ioc.tags.join(', '))
    setEditId(ioc.id)
    setShowForm(true)
  }

  const handleSubmit = () => {
    if (!form.value?.trim()) return
    const tags = tagInput.split(',').map(t => t.trim()).filter(Boolean)
    if (editId) {
      save(iocs.map(i => i.id === editId ? { ...i, ...form, tags, lastSeen: now() } as IOC : i))
    } else {
      const newIOC: IOC = {
        id: crypto.randomUUID(),
        value: form.value!.trim(),
        type: detectIOCType(form.value!.trim()),
        severity: form.severity as IOC['severity'] || 'Medium',
        status: form.status as IOC['status'] || 'Active',
        source: form.source || '',
        notes: form.notes || '',
        tags,
        timestamp: now(),
        lastSeen: now(),
      }
      save([newIOC, ...iocs])
    }
    setShowForm(false)
  }

  const deleteIOC = (id: string) => {
    if (confirm('Delete this IOC?')) save(iocs.filter(i => i.id !== id))
  }

  const updateStatus = (id: string, status: IOC['status']) => {
    save(iocs.map(i => i.id === id ? { ...i, status, lastSeen: now() } : i))
  }

  const bulkImport = () => {
    const lines = bulkInput.split('\n').map(l => l.trim()).filter(Boolean)
    const newIOCs: IOC[] = lines.map(line => ({
      id: crypto.randomUUID(),
      value: line,
      type: detectIOCType(line),
      severity: 'Medium',
      status: 'Active',
      source: 'Bulk Import',
      notes: '',
      tags: [],
      timestamp: now(),
      lastSeen: now(),
    }))
    save([...newIOCs, ...iocs])
    setBulkInput('')
    setShowBulk(false)
  }

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const exportAll = () => downloadJSON(iocs, 'iocs.json')
  const exportCSV = () => {
    const rows = iocs.map(i => ({ value: i.value, type: i.type, severity: i.severity, status: i.status, source: i.source, tags: i.tags.join('|'), notes: i.notes, timestamp: i.timestamp }))
    downloadText(toCSV(rows), 'iocs.csv', 'text/csv')
  }
  const exportDefanged = () => {
    const lines = iocs.map(i => defang(i.value)).join('\n')
    downloadText(lines, 'iocs_defanged.txt')
  }

  const filtered = iocs.filter(i => {
    const q = filter.toLowerCase()
    const matchQ = !q || i.value.toLowerCase().includes(q) || i.tags.some(t => t.toLowerCase().includes(q)) || i.source.toLowerCase().includes(q)
    const matchT = filterType === 'All' || i.type === filterType
    const matchS = filterSev === 'All' || i.severity === filterSev
    const matchSt = filterStatus === 'All' || i.status === filterStatus
    return matchQ && matchT && matchS && matchSt
  })

  const types = ['All', ...Array.from(new Set(iocs.map(i => i.type)))]

  const sevColor: Record<string, string> = {
    Critical: 'badge-critical', High: 'badge-high', Medium: 'badge-medium', Low: 'badge-low', Info: 'badge-info'
  }

  return (
    <div className="space-y-5">
      <div className="flex items-start justify-between flex-wrap gap-4">
        <div>
          <h2 className="section-heading">IOC Manager</h2>
          <p className="section-subheading">Track and manage Indicators of Compromise</p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button onClick={() => setShowBulk(!showBulk)} className="btn-primary">Bulk Import</button>
          <button onClick={openNew} className="btn-success">+ Add IOC</button>
          <button onClick={exportCSV} className="btn-primary">Export CSV</button>
          <button onClick={exportDefanged} className="btn-primary">Export Defanged</button>
          <button onClick={exportAll} className="btn-primary">Export JSON</button>
        </div>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-3 md:grid-cols-6 gap-3">
        {SEVERITIES.map(s => (
          <div key={s} className="stat-card">
            <div className="text-xs text-gray-500">{s}</div>
            <div className="text-xl font-bold" style={{ color: { Critical: '#ff4444', High: '#ff6b35', Medium: '#ffd700', Low: '#00d4ff', Info: '#00ffcc' }[s] }}>
              {iocs.filter(i => i.severity === s).length}
            </div>
          </div>
        ))}
        <div className="stat-card">
          <div className="text-xs text-gray-500">Total</div>
          <div className="text-xl font-bold text-blue-400">{iocs.length}</div>
        </div>
      </div>

      {/* Bulk import */}
      {showBulk && (
        <div className="card">
          <div className="card-header"><span className="card-title">Bulk Import IOCs</span></div>
          <p className="text-xs text-gray-500 mb-2">Paste one IOC per line (IPs, domains, hashes, URLs). Type will be auto-detected.</p>
          <textarea
            className="cyber-textarea w-full h-32 mb-3"
            value={bulkInput}
            onChange={e => setBulkInput(e.target.value)}
            placeholder={`192.168.1.1\nmalicious.com\nd41d8cd98f00b204e9800998ecf8427e`}
          />
          <div className="flex gap-2">
            <button onClick={bulkImport} disabled={!bulkInput.trim()} className="btn-success disabled:opacity-50">Import {bulkInput.split('\n').filter(l => l.trim()).length} IOCs</button>
            <button onClick={() => setShowBulk(false)} className="btn-danger">Cancel</button>
          </div>
        </div>
      )}

      {/* Add/Edit form */}
      {showForm && (
        <div className="card border-glow-blue">
          <div className="card-header">
            <span className="card-title">{editId ? 'Edit IOC' : 'Add New IOC'}</span>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <label className="text-xs text-gray-400 mb-1 block">IOC Value *</label>
              <input
                className="cyber-input"
                value={form.value || ''}
                onChange={e => setForm(f => ({ ...f, value: e.target.value, type: detectIOCType(e.target.value) }))}
                placeholder="IP, domain, hash, URL..."
              />
              {form.value && <div className="text-xs text-gray-500 mt-1">Detected: {detectIOCType(form.value)}</div>}
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Severity</label>
              <select className="cyber-select w-full" value={form.severity} onChange={e => setForm(f => ({ ...f, severity: e.target.value as IOC['severity'] }))}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Status</label>
              <select className="cyber-select w-full" value={form.status} onChange={e => setForm(f => ({ ...f, status: e.target.value as IOC['status'] }))}>
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Source</label>
              <input className="cyber-input" value={form.source || ''} onChange={e => setForm(f => ({ ...f, source: e.target.value }))} placeholder="e.g., SIEM alert, Threat feed, Manual" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Tags (comma-separated)</label>
              <input className="cyber-input" value={tagInput} onChange={e => setTagInput(e.target.value)} placeholder="ransomware, c2, phishing" />
            </div>
            <div>
              <label className="text-xs text-gray-400 mb-1 block">Notes</label>
              <input className="cyber-input" value={form.notes || ''} onChange={e => setForm(f => ({ ...f, notes: e.target.value }))} placeholder="Additional context..." />
            </div>
          </div>
          <div className="flex gap-2 mt-4">
            <button onClick={handleSubmit} className="btn-success">{editId ? 'Save Changes' : 'Add IOC'}</button>
            <button onClick={() => setShowForm(false)} className="btn-danger">Cancel</button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="card">
        <div className="flex flex-wrap gap-3">
          <input className="cyber-input flex-1 min-w-[200px]" value={filter} onChange={e => setFilter(e.target.value)} placeholder="Search IOCs..." />
          <select className="cyber-select w-36" value={filterType} onChange={e => setFilterType(e.target.value)}>
            {types.map(t => <option key={t} value={t}>{t === 'All' ? 'All Types' : t}</option>)}
          </select>
          <select className="cyber-select w-36" value={filterSev} onChange={e => setFilterSev(e.target.value)}>
            <option value="All">All Severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
          <select className="cyber-select w-40" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
            <option value="All">All Statuses</option>
            {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="text-xs text-gray-500 mt-2">Showing {filtered.length} of {iocs.length} IOCs</div>
      </div>

      {/* Table */}
      {filtered.length === 0 ? (
        <div className="text-center py-16 text-gray-500">
          <div className="text-4xl mb-3">📌</div>
          <div>{iocs.length === 0 ? 'No IOCs tracked yet. Click "+ Add IOC" to get started.' : 'No IOCs match your filters.'}</div>
        </div>
      ) : (
        <div className="card overflow-x-auto">
          <table className="cyber-table w-full">
            <thead>
              <tr>
                <th>Value</th>
                <th>Type</th>
                <th>Severity</th>
                <th>Status</th>
                <th>Source</th>
                <th>Tags</th>
                <th>Added</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(ioc => (
                <tr key={ioc.id}>
                  <td>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs text-gray-200 max-w-[180px] truncate" title={ioc.value}>{ioc.value}</span>
                      <button onClick={() => copy(ioc.value, ioc.id)} className="text-xs text-blue-400 hover:text-blue-300 shrink-0">
                        {copied === ioc.id ? '✓' : '⧉'}
                      </button>
                    </div>
                    {ioc.notes && <div className="text-xs text-gray-600 mt-0.5 truncate max-w-[180px]">{ioc.notes}</div>}
                  </td>
                  <td><span className="badge badge-info">{ioc.type}</span></td>
                  <td><span className={`badge ${sevColor[ioc.severity]}`}>{ioc.severity}</span></td>
                  <td>
                    <select
                      className="text-xs bg-transparent border-none outline-none cursor-pointer"
                      style={{ color: ioc.status === 'Active' ? '#ff4444' : ioc.status === 'Resolved' ? '#39ff14' : '#ffd700' }}
                      value={ioc.status}
                      onChange={e => updateStatus(ioc.id, e.target.value as IOC['status'])}
                    >
                      {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </td>
                  <td className="text-xs">{ioc.source || '—'}</td>
                  <td>
                    <div className="flex flex-wrap gap-1">
                      {ioc.tags.map(tag => <span key={tag} className="badge badge-info text-xs">{tag}</span>)}
                    </div>
                  </td>
                  <td className="text-xs whitespace-nowrap">{formatDate(ioc.timestamp)}</td>
                  <td>
                    <div className="flex gap-1">
                      <button onClick={() => openEdit(ioc)} className="text-xs text-blue-400 hover:underline">Edit</button>
                      <span className="text-gray-600">|</span>
                      <button onClick={() => deleteIOC(ioc.id)} className="text-xs text-red-400 hover:underline">Del</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
