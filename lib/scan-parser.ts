export type PortRecord = {
  host: string;
  protocol: string;
  port: number;
  state: string;
  service: string;
  product: string;
  version: string;
};

export type HostRecord = {
  ip: string;
  status: string;
  os: string;
  ports: PortRecord[];
  vulnerabilities: string[];
};

export type ScanDataset = {
  source: string;
  scanner: string;
  startedAt: string;
  hosts: HostRecord[];
};

const HIGH_RISK_PORTS = new Set([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 389, 443, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 9200]);


const attr = (el: Element | null | undefined, key: string, fallback = 'Unknown'): string => el?.getAttribute(key)?.trim() || fallback;

export const parseNmapXml = (xmlString: string, source: string): ScanDataset => {
  const parser = new DOMParser();
  const doc = parser.parseFromString(xmlString, 'application/xml');

  if (doc.querySelector('parsererror')) {
    throw new Error('Invalid XML format. Please upload an Nmap XML export.');
  }

  const runStats = doc.querySelector('nmaprun');
  const hosts = Array.from(doc.querySelectorAll('host')).map((hostNode) => {
    const ipNode = hostNode.querySelector('address[addrtype="ipv4"], address[addrtype="ipv6"], address');
    const statusNode = hostNode.querySelector('status');
    const osNode = hostNode.querySelector('os > osmatch');

    const ports: PortRecord[] = Array.from(hostNode.querySelectorAll('port')).map((portNode) => {
      const serviceNode = portNode.querySelector('service');
      return {
        host: attr(ipNode, 'addr', 'Unknown host'),
        protocol: attr(portNode, 'protocol', 'tcp'),
        port: Number(attr(portNode, 'portid', '0')),
        state: attr(portNode.querySelector('state'), 'state', 'unknown'),
        service: attr(serviceNode, 'name', 'unknown'),
        product: attr(serviceNode, 'product', ''),
        version: attr(serviceNode, 'version', ''),
      };
    });

    const vulnerabilities = ports
      .filter((item) => item.state === 'open' && HIGH_RISK_PORTS.has(item.port))
      .map((item) => `${item.protocol}/${item.port} (${item.service}) exposed`);

    return {
      ip: attr(ipNode, 'addr', 'Unknown host'),
      status: attr(statusNode, 'state', 'unknown'),
      os: attr(osNode, 'name', 'Not fingerprinted'),
      ports,
      vulnerabilities,
    };
  });

  return {
    source,
    scanner: attr(runStats, 'scanner', 'nmap'),
    startedAt: attr(runStats, 'startstr', new Date().toISOString()),
    hosts,
  };
};

export const flattenOpenPorts = (dataset: ScanDataset): PortRecord[] =>
  dataset.hosts.flatMap((host) => host.ports.filter((port) => port.state === 'open').map((port) => ({ ...port, host: host.ip })));

export const summarizeRisk = (dataset: ScanDataset) => {
  const openPorts = flattenOpenPorts(dataset);
  const highRisk = openPorts.filter((port) => HIGH_RISK_PORTS.has(port.port));
  const externalFacing = openPorts.filter((port) => [80, 443, 8080, 8443].includes(port.port));

  return {
    hostsDiscovered: dataset.hosts.length,
    aliveHosts: dataset.hosts.filter((host) => host.status === 'up').length,
    openPorts: openPorts.length,
    highRiskFindings: highRisk.length,
    externalServices: externalFacing.length,
  };
};
