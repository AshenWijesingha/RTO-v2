import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'Red Team Player | Live Scan Workspace',
  description: 'Upload real Nmap XML scan data, triage findings, and track actionable red-team priorities.',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
