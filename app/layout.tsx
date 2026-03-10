import type { Metadata } from 'next'
import './globals.css'

export const metadata: Metadata = {
  title: 'Blue Team Cyber Dashboard | Threat Analysis & Incident Response',
  description: 'Professional Blue Team Cyber Security Dashboard for threat analysis, IOC management, incident response, threat hunting, and vulnerability management.',
  keywords: 'blue team, cyber security, incident response, threat intelligence, IOC, SIEM, vulnerability management',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="cyber-grid">{children}</body>
    </html>
  )
}
