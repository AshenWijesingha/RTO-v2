'use client';

import { ChangeEvent, useMemo, useState } from 'react';
import { flattenOpenPorts, parseNmapXml, summarizeRisk, type ScanDataset } from '@/lib/scan-parser';

const emptyState = `<?xml version="1.0"?>\n<nmaprun scanner="nmap" startstr="Sample">\n  <host>\n    <status state="up"/>\n    <address addr="10.10.10.10" addrtype="ipv4"/>\n    <ports>\n      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9"/></port>\n      <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.22"/></port>\n    </ports>\n  </host>\n</nmaprun>`;

export default function HomePage() {
  const [dataset, setDataset] = useState<ScanDataset | null>(null);
  const [error, setError] = useState('');
  const [activeHost, setActiveHost] = useState<string>('');

  const summary = useMemo(() => (dataset ? summarizeRisk(dataset) : null), [dataset]);
  const openPorts = useMemo(() => (dataset ? flattenOpenPorts(dataset) : []), [dataset]);

  const onUpload = async (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      setError('');
      const xml = await file.text();
      const parsed = parseNmapXml(xml, file.name);
      setDataset(parsed);
      setActiveHost(parsed.hosts[0]?.ip ?? '');
    } catch (uploadError) {
      setDataset(null);
      setError(uploadError instanceof Error ? uploadError.message : 'Upload failed.');
    }
  };

  const selectedHost = dataset?.hosts.find((host) => host.ip === activeHost) ?? dataset?.hosts[0];

  return (
    <main className="page">
      <section className="hero card">
        <div>
          <p className="eyebrow">Operational workspace</p>
          <h1>Red Team Player</h1>
          <p className="muted">Upload real Nmap XML exports to turn reconnaissance data into immediate operator priorities.</p>
        </div>
        <label className="upload">
          <span>Upload Nmap XML</span>
          <input type="file" accept=".xml,text/xml" onChange={onUpload} />
        </label>
      </section>

      {error && <p className="error">{error}</p>}

      {!dataset && (
        <section className="card empty">
          <h2>No scan loaded</h2>
          <p>Export your scan with <code>-oX scan.xml</code> and upload it here. This app processes the file locally in your browser.</p>
          <pre>{emptyState}</pre>
        </section>
      )}

      {dataset && summary && (
        <>
          <section className="grid stats">
            <article className="card"><p>Hosts discovered</p><strong>{summary.hostsDiscovered}</strong></article>
            <article className="card"><p>Alive hosts</p><strong>{summary.aliveHosts}</strong></article>
            <article className="card"><p>Open ports</p><strong>{summary.openPorts}</strong></article>
            <article className="card danger"><p>High-risk exposures</p><strong>{summary.highRiskFindings}</strong></article>
          </section>

          <section className="grid split">
            <article className="card">
              <h2>Host inventory</h2>
              <p className="muted">Source: {dataset.source} · Scanner: {dataset.scanner} · Started: {dataset.startedAt}</p>
              <div className="host-list">
                {dataset.hosts.map((host) => (
                  <button key={host.ip} className={host.ip === selectedHost?.ip ? 'host active' : 'host'} onClick={() => setActiveHost(host.ip)}>
                    <span>{host.ip}</span>
                    <small>{host.status} · {host.ports.filter((port) => port.state === 'open').length} open</small>
                  </button>
                ))}
              </div>
            </article>

            <article className="card">
              <h2>Selected host detail</h2>
              {selectedHost ? (
                <>
                  <p><strong>IP:</strong> {selectedHost.ip}</p>
                  <p><strong>OS guess:</strong> {selectedHost.os}</p>
                  <p><strong>Status:</strong> {selectedHost.status}</p>
                  <h3>Immediate checks</h3>
                  <ul>
                    {selectedHost.vulnerabilities.length > 0 ? (
                      selectedHost.vulnerabilities.map((item) => <li key={item}>{item}</li>)
                    ) : (
                      <li>No high-risk ports mapped by baseline profile.</li>
                    )}
                  </ul>
                </>
              ) : <p>No hosts in scan.</p>}
            </article>
          </section>

          <section className="card">
            <h2>Open service matrix</h2>
            <table>
              <thead>
                <tr>
                  <th>Host</th>
                  <th>Port</th>
                  <th>Service</th>
                  <th>Product</th>
                  <th>Version</th>
                </tr>
              </thead>
              <tbody>
                {openPorts.map((port) => (
                  <tr key={`${port.host}-${port.protocol}-${port.port}`}>
                    <td>{port.host}</td>
                    <td>{port.protocol}/{port.port}</td>
                    <td>{port.service}</td>
                    <td>{port.product || '-'}</td>
                    <td>{port.version || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      )}
    </main>
  );
}
