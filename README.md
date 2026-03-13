# Blue Team Cyber Dashboard v2

A professional Blue Team Cyber Security Dashboard built with **Next.js 15** and **TypeScript**. Designed for authorized security assessments, threat analysis, incident response, and reporting workflows.

## ⚠️ Important Scope & Ethics

This project is for authorized penetration testing and cybersecurity research only.
Unauthorized use of any scanning or intelligence-gathering features against systems without explicit permission is illegal.

## Features

- **Dark neon cyberpunk UI** with glassmorphism design and Tailwind CSS
- **Dashboard** — overview of IOCs, incidents, and quick-action shortcuts
- **Threat Intelligence** — IP/domain analysis, DNS lookups, WHOIS/RDAP
- **IOC Manager** — add, tag, search, and export indicators of compromise
- **Incident Response** — track and manage security incidents through lifecycle
- **Threat Hunting** — hypothesis-based hunting with MITRE ATT&CK mapping
- **SIEM Query Builder** — generate KQL, SPL, and Sigma queries
- **Vulnerability Management** — CVSSv3 scoring, CVE tracking, remediation
- **Log Analysis** — parse and search log entries with pattern detection
- **Network Analysis** — network topology tools and packet analysis helpers
- **Security Checklists** — customizable security hardening checklists
- **Encode / Decode** — Base64, Hex, URL, ROT13, Binary, and hash detection
- **Report Generator** — compile findings into professional security reports
- **Settings** — theme customization and persistent preferences via localStorage

## Tech Stack

- [Next.js 15](https://nextjs.org/) — React framework with static export
- [TypeScript](https://www.typescriptlang.org/) — type-safe components
- [Tailwind CSS](https://tailwindcss.com/) — utility-first styling
- Deployed on **GitHub Pages** via GitHub Actions

## Project Structure

```
.
├── app/                   # Next.js App Router
│   ├── globals.css        # Global styles and CSS variables
│   ├── layout.tsx         # Root HTML layout and metadata
│   └── page.tsx           # Main page with section routing
├── components/            # Feature-level React components
│   ├── Dashboard.tsx
│   ├── ThreatIntelligence.tsx
│   ├── IOCManager.tsx
│   ├── IncidentResponse.tsx
│   ├── ThreatHunting.tsx
│   ├── SIEMQueryBuilder.tsx
│   ├── VulnerabilityManagement.tsx
│   ├── LogAnalysis.tsx
│   ├── NetworkAnalysis.tsx
│   ├── SecurityChecklists.tsx
│   ├── EncodeDecode.tsx
│   ├── ReportGenerator.tsx
│   ├── Navigation.tsx
│   └── Settings.tsx
├── lib/
│   └── utils.ts           # Shared utilities (encoding, localStorage, CVSS, etc.)
├── .github/
│   └── workflows/
│       └── deploy.yml     # GitHub Actions — build and deploy to GitHub Pages
├── next.config.js         # Next.js static export configuration
├── tailwind.config.js
└── tsconfig.json
```

## Run Locally

```bash
npm install
npm run dev
```

Then visit `http://localhost:3000`.

## Build for Production

```bash
npm run build
```

Static output is generated in the `out/` directory.

## Deploy to GitHub Pages

The project is automatically deployed via GitHub Actions on every push to `main`.

### Manual Setup

1. Push repository to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set Source to **GitHub Actions**.
4. Push to `main` — the workflow in `.github/workflows/deploy.yml` will build and deploy automatically.

The live site will be available at:
```
https://<your-username>.github.io/RTO-v2/
```

### Environment Variables

The `NEXT_PUBLIC_BASE_PATH` variable is set automatically in the workflow to `/RTO-v2` (matching the repo name) so assets are correctly served from GitHub Pages.

## API Keys (Optional)

Some threat intelligence features can use external APIs. Create a local `api-keys.json` file (see the structure below) and fill in your keys. **Never commit `api-keys.json` to the repository** — it is listed in `.gitignore`.

```json
{
  "shodan": "<your-shodan-api-key>",
  "vuldb": "<your-vuldb-api-key>",
  "greynoise": "<your-greynoise-api-key>",
  "fullhunt": "<your-fullhunt-api-key>",
  "zap": {
    "url": "http://localhost:8080",
    "apiKey": "<your-zap-api-key>"
  }
}
```

| Service     | Usage |
|-------------|-------|
| Shodan      | Internet-connected device search |
| GreyNoise   | IP reputation and noise classification |
| FullHunt    | Attack surface discovery |
| VulDB       | Vulnerability database lookups |

## Deploy to Cloudflare Pages

You can host this project on [Cloudflare Pages](https://pages.cloudflare.com/) as a static site — no backend or server-side runtime required.

### Automatic deployment (recommended)

1. Push the repository to GitHub (or any supported Git provider).
2. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/) and go to **Workers & Pages → Create → Pages → Connect to Git**.
3. Select your repository and click **Begin setup**.
4. Configure the build settings:

   | Setting | Value |
   |---|---|
   | **Framework preset** | Next.js (Static HTML Export) |
   | **Build command** | `npm run build` |
   | **Build output directory** | `out` |
   | **Node.js version** (env var `NODE_VERSION`) | `22` |

5. Leave **NEXT_PUBLIC_BASE_PATH** unset (the site will be served from the root of your `*.pages.dev` domain).
6. Click **Save and Deploy**. Cloudflare will install dependencies, run `npm run build`, and publish the `out/` directory automatically on every push to `main`.

Your live site will be available at:
```
https://<your-project-name>.pages.dev
```

### Manual deployment via Wrangler CLI

```bash
# Install Wrangler (Cloudflare's CLI)
npm install -g wrangler

# Authenticate
wrangler login

# Build the static output
npm run build

# Deploy the out/ directory to Cloudflare Pages
wrangler pages deploy out --project-name=<your-project-name>
```

### Notes

- The `output: 'export'` setting in `next.config.js` generates a fully static site in the `out/` directory — no Node.js runtime is needed at serve time, which is why Cloudflare Pages (a CDN/edge platform) works perfectly.
- Do **not** set `NEXT_PUBLIC_BASE_PATH` for a Cloudflare Pages deployment; the project is served from the domain root (`/`), so no path prefix is needed.
- Cloudflare Pages enforces a **25 MiB** limit per file and a **20,000 file** limit per deployment. This project's static export is well within those limits.

## Notes for Real-World Operations

Because this application runs entirely in the browser (no backend), browser security constraints apply:

- CORS policies may block direct API calls to some external services.
- No raw socket access from JavaScript (cannot perform true TCP/UDP port scanning like Nmap).
- Some panels provide best-effort passive lookups using public endpoints and degrade gracefully when blocked.

If you need real active scanning and reliable telemetry, pair this UI with a dedicated authorized backend/API gateway under your control and strict legal scope.

