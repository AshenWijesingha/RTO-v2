# Red Team Operator Cyber Dashboard v2 (Static GitHub Pages Build)

A single-file, front-end cyber intelligence dashboard designed for **authorized** security assessments, education, and reporting workflows.

## ⚠️ Important Scope & Ethics

This project is for authorized penetration testing and cybersecurity research only.
Unauthorized scanning of systems without explicit permission is illegal.

Because this application is intentionally **backend-free** (for GitHub Pages hosting), browser security constraints apply:

- No raw socket access from JavaScript (cannot perform true SYN/TCP/UDP port scanning like Nmap).
- CORS and target policies can block header/status inspection for many domains.
- Some panels use best-effort passive/public endpoints where available and degrade gracefully when blocked.

## Features

- Dark neon cyberpunk UI with glassmorphism and matrix canvas animation.
- Target Analysis Panel with tabbed intelligence views:
  - Domain parsing + TLD/subdomain extraction
  - Passive DNS queries (Google DNS JSON API)
  - SSL/TLS summary with browser-safe constraints
  - Port panel UI (intel/demo-based status)
  - WHOIS/RDAP lookup (domain)
  - Security headers checklist UI
  - HTTP inspector (best effort, CORS-permitting)
  - Technology detection panel (static guidance)
- Red Team Lifecycle collapsible knowledge base.
- Nmap command library with copy buttons + "Copied" feedback.
- Enumeration script library with copy buttons.
- Live search + dynamic highlight.
- Smart Nmap command builder.
- Terminal mode modal (`help` supported).
- Theme switcher (Green / Purple / Blue).
- Interactive checklist with localStorage persistence + progress bar + reset.
- Scroll progress line and responsive sidebar/hamburger menu.

## Project Structure

This repository intentionally contains only:

- `index.html` — complete application (HTML/CSS/JS in one file)
- `README.md`

## Run Locally

Open `index.html` directly in your browser, or run a static file server:

```bash
python -m http.server 8080
```

Then visit `http://localhost:8080`.

## Deploy to GitHub Pages

1. Push repository to GitHub.
2. Go to **Settings → Pages**.
3. Under **Build and deployment**, set Source to **Deploy from a branch**.
4. Select your branch (e.g., `main`) and `/ (root)` folder.
5. Save and wait for deployment.

## Notes for Real-World Operations

If you need real active scanning and reliable scanning telemetry, pair this UI with a dedicated authorized backend/API gateway under your control and strict legal scope.

