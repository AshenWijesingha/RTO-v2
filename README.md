# Red Team Player (Next.js)

A static-exportable Next.js application for red-team operators to ingest **real Nmap XML scan data** and prioritize host/service exposure.

## Features

- Upload actual `nmap -oX scan.xml` output (processed locally in-browser).
- Host inventory with operating system hints and live status.
- Open service matrix and baseline high-risk exposure highlighting.
- GitHub Pages compatible (`next build` with `output: export`).

## Run locally

```bash
npm install
npm run dev
```

## Build for GitHub Pages

```bash
npm run build
```

The static site is generated in `out/`.
