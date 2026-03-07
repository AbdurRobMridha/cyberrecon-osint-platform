# 🔍 OSINT Recon Engine

> **Username Intelligence System** — Scan 50+ platforms in real-time to discover where a username exists across the internet.

[![Live Demo](https://img.shields.io/badge/Live-Demo-00f5ff?style=for-the-badge)](https://osint-recon-engine-backend-production.up.railway.app)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs)](https://nodejs.org)
[![Express](https://img.shields.io/badge/Express-4.x-000000?style=for-the-badge&logo=express)](https://expressjs.com)

---

## ✨ Features

- 🔎 **Real HTTP scanning** — actual requests to each platform, not simulations
- ⚡ **Live results via SSE** — cards stream in as each platform is checked
- 🔐 **JWT Authentication** — sign up / sign in before scanning
- 📊 **Smart detection** — 3-layer analysis: HTTP codes + body content + positive confirmation
- 🌐 **50+ platforms** — Developer, Social, Professional, Content, Gaming, Design, Forum, Blog
- 🧠 **3D Intelligence Graph** — Three.js visualization of detected accounts
- 🟡 **UNCERTAIN status** — flags ambiguous results for manual verification
- 🟢🟠🔴 **Color-coded buttons** — VISIT / VERIFY / CHECK per result confidence

---

## 🖥️ Screenshots

| Auth Page | Dashboard |
|---|---|
| Cyberpunk sign-in/sign-up | Real-time scan results with 3D graph |

---

## 🚀 Quick Start (Local)

```bash
# 1. Install dependencies
npm install

# 2. Create .env
echo "JWT_SECRET=yourSecretHere" > .env

# 3. Start server
node server.js

# 4. Open browser
# http://localhost:3001/auth.html
```

---

## 📡 Platform Categories

| Category | Platforms |
|---|---|
| 👨‍💻 Developer | GitHub, GitLab, Bitbucket, StackOverflow, Dev.to, CodePen, Replit, HackerRank, LeetCode, Kaggle + more |
| 📱 Social | Reddit, TikTok, Pinterest, Threads, Instagram, X, Facebook, Snapchat |
| 💼 Professional | LinkedIn, AngelList, ResearchGate, ORCID |
| 🎬 Content | YouTube, Twitch, Medium, Substack, SoundCloud, Spotify |
| 🎮 Gaming | Steam, Epic Games, PSN Profiles |
| 🎨 Design | Dribbble, Behance, ArtStation |
| 💬 Forum | Quora, ProductHunt, Hashnode, Disqus |
| 📝 Blog | WordPress, Blogger, Ghost |
| 🔍 OSINT | Gravatar, About.me, Keybase, BuyMeACoffee, Patreon |

---

## 🏗️ Architecture

```
Browser (Netlify / Railway static)
    │
    ├── auth.html  →  POST /api/auth/register  ┐
    │                 POST /api/auth/login      ├── Express + bcrypt + JWT
    │                                           │
    └── index.html →  GET  /api/scan/:username ─┤  SSE stream
                      (EventSource / SSE)        └── axios → real HTTP checks
```

### Detection Logic

```
HTTP 404           → NOT FOUND  ✅ reliable
HTTP 403/429/503   → BLOCKED    (server IP blocked by platform)
HTTP 200 + body notFoundStrings → NOT FOUND  ✅ catches false positives
HTTP 200 + foundStrings match  → FOUND       ✅ positively confirmed
HTTP 200 + no match            → UNCERTAIN ⚠️ (manual verify button shown)
```

---

## 🔧 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Node.js, Express.js |
| Auth | JWT (`jsonwebtoken`), bcrypt (`bcryptjs`) |
| Scanning | Axios with browser-like headers |
| Streaming | Server-Sent Events (SSE) |
| Frontend | Vanilla HTML/CSS/JS |
| 3D Graph | Three.js |
| Storage | Flat-file `users.json` |

---

## 🌍 Deployment (Railway)

1. Push to GitHub
2. [railway.app](https://railway.app) → New Project → Import repo
3. Set env vars: `JWT_SECRET=yourSecret` · `PORT=3001`
4. Generate domain → your app is live

---

## ⚠️ Disclaimer

This tool is for **educational and ethical OSINT purposes only**.  
Always respect platforms' Terms of Service. Do not use to harass, stalk, or harm individuals.  
The author is not responsible for misuse.

---

## 📄 License

MIT — free to use, modify, and distribute.