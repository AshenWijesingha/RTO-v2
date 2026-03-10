'use client'

import React, { useState } from 'react'
import { base64Encode, base64Decode, hexEncode, hexDecode, urlEncode, urlDecode, rot13, htmlEncode, htmlDecode, binaryEncode, binaryDecode, identifyHash, copyToClipboard } from '@/lib/utils'

type EncodeMode = 'base64' | 'hex' | 'url' | 'rot13' | 'html' | 'binary'

const MODES: { id: EncodeMode; label: string }[] = [
  { id: 'base64', label: 'Base64' },
  { id: 'hex', label: 'Hex' },
  { id: 'url', label: 'URL' },
  { id: 'rot13', label: 'ROT13' },
  { id: 'html', label: 'HTML Entities' },
  { id: 'binary', label: 'Binary' },
]

export default function EncodeDecode() {
  const [mode, setMode] = useState<EncodeMode>('base64')
  const [input, setInput] = useState('')
  const [encoded, setEncoded] = useState('')
  const [decoded, setDecoded] = useState('')
  const [hashInput, setHashInput] = useState('')
  const [hashType, setHashType] = useState('')
  const [copied, setCopied] = useState('')
  const [activeTab, setActiveTab] = useState<'encode-decode' | 'hash'>('encode-decode')

  const copy = async (text: string, key: string) => {
    await copyToClipboard(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 1500)
  }

  const encode = () => {
    if (!input.trim()) return
    try {
      switch (mode) {
        case 'base64': setEncoded(base64Encode(input)); break
        case 'hex': setEncoded(hexEncode(input)); break
        case 'url': setEncoded(urlEncode(input)); break
        case 'rot13': setEncoded(rot13(input)); break
        case 'html': setEncoded(htmlEncode(input)); break
        case 'binary': setEncoded(binaryEncode(input)); break
      }
    } catch (e) {
      setEncoded(`Error: ${e instanceof Error ? e.message : 'Unknown error'}`)
    }
  }

  const decode = () => {
    if (!input.trim()) return
    try {
      switch (mode) {
        case 'base64': setDecoded(base64Decode(input)); break
        case 'hex': setDecoded(hexDecode(input)); break
        case 'url': setDecoded(urlDecode(input)); break
        case 'rot13': setDecoded(rot13(input)); break
        case 'html': setDecoded(htmlDecode(input)); break
        case 'binary': setDecoded(binaryDecode(input)); break
      }
    } catch (e) {
      setDecoded(`Error: ${e instanceof Error ? e.message : 'Unknown error'}`)
    }
  }

  const identHash = () => {
    if (!hashInput.trim()) return
    setHashType(identifyHash(hashInput))
  }

  const HASH_REFERENCE = [
    { name: 'MD5', length: 32, example: 'd41d8cd98f00b204e9800998ecf8427e', broken: true },
    { name: 'SHA-1', length: 40, example: 'da39a3ee5e6b4b0d3255bfef95601890afd80709', broken: true },
    { name: 'SHA-256', length: 64, example: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', broken: false },
    { name: 'SHA-512', length: 128, example: 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e', broken: false },
    { name: 'bcrypt', length: 60, example: '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', broken: false },
    { name: 'NTLM', length: 32, example: 'AAD3B435B51404EEAAD3B435B51404EE', broken: true },
    { name: 'SHA-384', length: 96, example: '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b', broken: false },
  ]

  const ANALYSIS_EXAMPLES = [
    { label: 'Base64 command (PowerShell)', input: 'powershell.exe -EncodedCommand JABjAD0AJwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8AdQBzAC4AYwBvAG0AJwA=', mode: 'base64' as EncodeMode },
    { label: 'Hex encoded payload', input: '4d5a90000300000004000000ffff0000b80000000000000040000000', mode: 'hex' as EncodeMode },
    { label: 'URL encoded path traversal', input: '%2F%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd', mode: 'url' as EncodeMode },
  ]

  return (
    <div className="space-y-5">
      <div>
        <h2 className="section-heading">Encode / Decode</h2>
        <p className="section-subheading">Analyze encoded payloads, decode IOCs, and identify hash types</p>
      </div>

      <div className="flex gap-2">
        {(['encode-decode', 'hash'] as const).map(t => (
          <button key={t} onClick={() => setActiveTab(t)} className={`tab-btn ${activeTab === t ? 'active' : ''}`}>
            {t === 'encode-decode' ? '⚙ Encode / Decode' : '🔐 Hash Identifier'}
          </button>
        ))}
      </div>

      {activeTab === 'encode-decode' && (
        <div className="space-y-4">
          {/* Mode selection */}
          <div className="card">
            <div className="card-header"><span className="card-title">Encoding Format</span></div>
            <div className="flex flex-wrap gap-2">
              {MODES.map(m => (
                <button key={m.id} onClick={() => { setMode(m.id); setEncoded(''); setDecoded('') }} className={`tab-btn ${mode === m.id ? 'active' : ''}`}>
                  {m.label}
                </button>
              ))}
            </div>
          </div>

          {/* Input */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Input</span>
              <button onClick={() => { setInput(''); setEncoded(''); setDecoded('') }} className="ml-auto text-xs text-gray-500 hover:text-red-400">Clear</button>
            </div>
            <textarea
              className="cyber-textarea w-full h-28 mb-3"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={`Enter text to encode/decode using ${MODES.find(m => m.id === mode)?.label}...`}
            />
            <div className="flex gap-2 flex-wrap">
              <button onClick={encode} disabled={!input.trim()} className="btn-primary disabled:opacity-50">Encode →</button>
              <button onClick={decode} disabled={!input.trim()} className="btn-success disabled:opacity-50">← Decode</button>
            </div>
          </div>

          {/* Results */}
          <div className="grid md:grid-cols-2 gap-4">
            {encoded && (
              <div className="card">
                <div className="flex items-center justify-between mb-2">
                  <span className="card-title">Encoded Output</span>
                  <div className="flex gap-2">
                    <button onClick={() => { setInput(encoded); setEncoded('') }} className="text-xs text-blue-400 hover:underline">Use as Input</button>
                    <button onClick={() => copy(encoded, 'encoded')} className="btn-primary text-xs py-1">{copied === 'encoded' ? '✓' : 'Copy'}</button>
                  </div>
                </div>
                <pre className="code-block text-xs whitespace-pre-wrap break-all">{encoded}</pre>
              </div>
            )}
            {decoded && (
              <div className="card">
                <div className="flex items-center justify-between mb-2">
                  <span className="card-title">Decoded Output</span>
                  <div className="flex gap-2">
                    <button onClick={() => { setInput(decoded); setDecoded('') }} className="text-xs text-blue-400 hover:underline">Use as Input</button>
                    <button onClick={() => copy(decoded, 'decoded')} className="btn-primary text-xs py-1">{copied === 'decoded' ? '✓' : 'Copy'}</button>
                  </div>
                </div>
                <pre className="code-block text-xs whitespace-pre-wrap break-all">{decoded}</pre>
              </div>
            )}
          </div>

          {/* Analysis examples */}
          <div className="card">
            <div className="card-header"><span className="card-title">Analyst Quick Examples</span></div>
            <div className="space-y-2">
              {ANALYSIS_EXAMPLES.map((ex, i) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded" style={{ background: 'rgba(10,20,40,0.5)', border: '1px solid rgba(0,212,255,0.06)' }}>
                  <div className="flex-1">
                    <div className="text-xs text-gray-400 mb-0.5">{ex.label}</div>
                    <code className="text-xs font-mono text-gray-500 break-all">{ex.input.substring(0, 60)}...</code>
                  </div>
                  <button
                    onClick={() => { setMode(ex.mode); setInput(ex.input); setEncoded(''); setDecoded('') }}
                    className="btn-primary text-xs py-1 shrink-0"
                  >
                    Load
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {activeTab === 'hash' && (
        <div className="space-y-4">
          <div className="card">
            <div className="card-header"><span className="card-title">Hash Identifier</span></div>
            <div className="flex gap-2">
              <input
                className="cyber-input flex-1"
                value={hashInput}
                onChange={e => setHashInput(e.target.value)}
                placeholder="Paste hash value here..."
                onKeyDown={e => e.key === 'Enter' && identHash()}
              />
              <button onClick={identHash} disabled={!hashInput.trim()} className="btn-primary disabled:opacity-50">Identify</button>
            </div>
            {hashType && (
              <div className="mt-3 p-3 rounded" style={{ background: 'rgba(0,212,255,0.06)', border: '1px solid rgba(0,212,255,0.2)' }}>
                <div className="text-xs text-gray-500 mb-1">Result:</div>
                <div className="text-sm font-semibold text-blue-400">{hashType}</div>
                <div className="text-xs text-gray-500 mt-1">Length: {hashInput.trim().length} characters</div>
              </div>
            )}
          </div>

          <div className="card">
            <div className="card-header"><span className="card-title">Hash Reference Table</span></div>
            <div className="overflow-x-auto">
              <table className="cyber-table">
                <thead>
                  <tr>
                    <th>Algorithm</th>
                    <th>Length</th>
                    <th>Status</th>
                    <th>Example</th>
                    <th>Copy</th>
                  </tr>
                </thead>
                <tbody>
                  {HASH_REFERENCE.map(h => (
                    <tr key={h.name}>
                      <td className="font-semibold text-blue-400">{h.name}</td>
                      <td>{h.length} chars</td>
                      <td>
                        {h.broken
                          ? <span className="badge badge-critical">Broken/Insecure</span>
                          : <span className="badge badge-success">Secure</span>
                        }
                      </td>
                      <td><code className="text-xs font-mono text-gray-500">{h.example.substring(0, 24)}...</code></td>
                      <td>
                        <button onClick={() => { setHashInput(h.example); setHashType('') }} className="text-xs text-blue-400 hover:underline">Load</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Hash lookup links */}
          <div className="card">
            <div className="card-header"><span className="card-title">Online Hash Lookup Resources</span></div>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
              {[
                { name: 'VirusTotal', url: `https://www.virustotal.com/gui/file/${hashInput.trim() || '[hash]'}`, desc: 'File/hash reputation' },
                { name: 'MalwareBazaar', url: `https://bazaar.abuse.ch/browse.php?search=${hashInput.trim() || '[hash]'}`, desc: 'Malware hash database' },
                { name: 'Any.run', url: 'https://any.run/malware-trends/', desc: 'Dynamic analysis' },
                { name: 'Hybrid Analysis', url: `https://www.hybrid-analysis.com/search?query=${hashInput.trim() || '[hash]'}`, desc: 'Sandbox analysis' },
                { name: 'Joe Sandbox', url: 'https://www.joesandbox.com/', desc: 'Deep malware analysis' },
                { name: 'HashKiller.io', url: 'https://hashkiller.io/listmanager', desc: 'Hash cracking lookup' },
              ].map(r => (
                <a key={r.name} href={r.url} target="_blank" rel="noopener noreferrer" className="glass-hover p-3 rounded-lg flex flex-col gap-1" style={{ border: '1px solid rgba(0,212,255,0.08)' }}>
                  <div className="text-xs font-semibold text-blue-400">{r.name}</div>
                  <div className="text-xs text-gray-500">{r.desc}</div>
                </a>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
