# OSINT Recon Engine — Username Intelligence System

#### YouTube Demo:  [https://youtu.be/mvBZcFMDspU](https://youtu.be/mvBZcFMDspU)
#### Preview Link: https://cyberrecon-osint-platform.onrender.com

#### Description:

**OSINT Recon Engine** is a full-stack web application that performs real-time Open Source Intelligence (OSINT) reconnaissance on a given username across 50+ platforms simultaneously. Built as my CS50 final project, it combines a Node.js backend with a cyberpunk-styled frontend to deliver a professional-grade username investigation tool.

---

## What It Does

You enter a username, hit **SCAN**, and the engine fires off parallel HTTP requests to dozens of platforms — from GitHub and Twitter to gaming networks, forums, design communities, and developer hubs. Each result streams back in real-time via **Server-Sent Events (SSE)**, so you watch results populate live rather than waiting for a full batch to complete.

Results are classified into four statuses:
- � **FOUND** — the username exists and is publicly accessible
- 🔴 **NOT FOUND** — no profile detected at that URL
- 🟠 **BLOCKED** — the platform rate-limited or blocked the scan
- 🟡 **UNCERTAIN** — ambiguous response requiring manual verification

---

## Key Features

- **Real-time streaming** — SSE delivers each result the moment it's ready, with a live progress bar and elapsed timer
- **3D Cyber Intelligence Graph** — built with Three.js, nodes appear on the globe as profiles are discovered; drag to rotate it interactively
- **Category filter tabs** — filter results by Developer, Social, Gaming, Professional, Content, Design, Forum, Blog, or OSINT platforms
- **JWT Authentication** — sign up / sign in guards the scanner; your token is stored in `localStorage` and verified server-side before any scan begins
- **Animated background** — 90-particle canvas system with connecting lines, creating the cyberpunk aesthetic
- **Glassmorphism UI** — dark theme using custom CSS variables with blur, glow effects, and micro-animations throughout

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | HTML5, Vanilla CSS, Vanilla JavaScript |
| 3D Visualization | Three.js (r128) |
| Backend | Node.js with Express |
| Auth | JSON Web Tokens (JWT) |
| Streaming | Server-Sent Events (SSE) |
| Fonts | JetBrains Mono, Orbitron, Inter (Google Fonts) |
| Deployment | Railway (backend) + Netlify (frontend) |

---

## Design Decisions

**Why SSE over WebSockets?** SSE is one-directional (server → client) which perfectly matches the scan flow — the frontend only needs to receive updates, not send them mid-scan. SSE is simpler to implement and works natively in the browser without a library.

**Why Vanilla JS (no framework)?** The project prioritizes understanding the DOM and browser APIs at a fundamental level, which aligns with CS50's philosophy. All state management, rendering, and event delegation are hand-rolled.

**Why Three.js for the graph?** A static result list felt insufficient for a "recon engine." A live 3D node graph where each discovered profile spawns a new sphere makes the data feel visceral and gives the tool a distinct visual identity.

**Ethical stance:** The tool only checks publicly accessible URLs and respects HTTP response codes. It is designed for educational and legitimate OSINT research (e.g., verifying your own digital footprint or investigating phishing actors).

---

## Project Structure

```
osint/
├── index.html       # Main scanner UI (auth-gated)
├── auth.html        # Login / sign-up page
├── app.js           # Frontend logic: SSE client, 3D graph, UI rendering
├── style.css        # Full cyberpunk dark theme (1000+ lines)
├── netlify.toml     # Netlify deployment config
└── README.md
```

---

*Built for CS50x — Harvard University's Introduction to Computer Science.*
