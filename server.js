/**
 * OSINT Recon Engine — Backend Server
 * Real HTTP scanning with smart body-content detection
 * JWT auth + SSE streaming
 */

'use strict';

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const axios = require('axios');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'osint_recon_super_secret_2024_change_in_prod';
const USERS_FILE = path.join(__dirname, 'users.json');

// ─── MIDDLEWARE ───────────────────────────────────────────────
app.use(cors({ origin: '*' }));
app.use(express.json());
app.use(express.static(__dirname));

// ─── USERS DB (flat-file) ─────────────────────────────────────
function loadUsers() {
    if (!fs.existsSync(USERS_FILE)) return [];
    try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
    catch { return []; }
}
function saveUsers(users) {
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────
function authRequired(req, res, next) {
    const token = req.headers.authorization?.split(' ')[1] || req.query.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });
    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: 'Invalid or expired token' });
    }
}

// ─── AUTH ROUTES ──────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
        return res.status(400).json({ error: 'All fields are required' });
    if (password.length < 6)
        return res.status(400).json({ error: 'Password must be at least 6 characters' });

    const users = loadUsers();
    if (users.find(u => u.email === email.toLowerCase()))
        return res.status(409).json({ error: 'Email already registered' });
    if (users.find(u => u.username.toLowerCase() === username.toLowerCase()))
        return res.status(409).json({ error: 'Username already taken' });

    const hash = await bcrypt.hash(password, 12);
    const user = { id: Date.now().toString(), username, email: email.toLowerCase(), password: hash, createdAt: new Date().toISOString() };
    users.push(user);
    saveUsers(users);

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

app.post('/api/auth/login', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password)
        return res.status(400).json({ error: 'Email and password are required' });

    const users = loadUsers();
    const user = users.find(u => u.email === email.toLowerCase());
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, username: user.username, email: user.email } });
});

app.get('/api/auth/me', authRequired, (req, res) => {
    res.json({ user: req.user });
});

// ─── PLATFORM DEFINITIONS ────────────────────────────────────
/**
 * Detection fields:
 *   notFoundOn      — HTTP codes that definitively mean NOT FOUND
 *   blockedOn       — HTTP codes that mean BLOCKED (we can't check)
 *   notFoundStrings — body substrings that prove the user does NOT exist
 *                     (platform returns 200 for missing users)
 *   foundStrings    — body substrings that positively confirm the user EXISTS
 *   mustConfirm     — if true, ONLY call FOUND when foundStrings match;
 *                     otherwise return UNCERTAIN (manual check needed)
 *   jsonItemsCheck  — special: parse JSON, look for exact username in items[]
 */
const PLATFORMS = [

    // ── Developer ──────────────────────────────────────────────────────────────
    {
        name: 'GitHub', cat: 'Developer', emoji: '🐙',
        url: 'https://github.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['not found', 'page you were looking for doesn\'t exist'],
        foundStrings: ['data-login', 'itemprop="name"'],
    },
    {
        name: 'GitLab', cat: 'Developer', emoji: '🦊',
        url: 'https://gitlab.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['user not found', 'page not found'],
        foundStrings: ['gl-avatar', '<meta property="og:title"'],
    },
    {
        name: 'Bitbucket', cat: 'Developer', emoji: '🪣',
        url: 'https://bitbucket.org/{u}',
        notFoundOn: [404],
        notFoundStrings: ["page not found", "this account does not exist", "we couldn't find"],
    },
    {
        // Uses the API — tells us exactly if the user exists
        name: 'StackOverflow', cat: 'Developer', emoji: '📦',
        url: 'https://api.stackexchange.com/2.3/users?order=desc&sort=reputation&inname={u}&site=stackoverflow&pagesize=5',
        notFoundOn: [],
        jsonItemsCheck: true,   // special handler below
    },
    {
        name: 'Dev.to', cat: 'Developer', emoji: '👩‍💻',
        url: 'https://dev.to/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', '404 | the dev'],
        foundStrings: ['crayons-avatar', 'profile-header'],
    },
    {
        name: 'CodePen', cat: 'Developer', emoji: '🖊️',
        url: 'https://codepen.io/{u}',
        notFoundOn: [404, 410],
        notFoundStrings: ['page not found'],
        foundStrings: ['profilePage', 'profile-name'],
    },
    {
        name: 'Replit', cat: 'Developer', emoji: '🔁',
        url: 'https://replit.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ["sorry, that user doesn't exist", 'page not found'],
    },
    {
        name: 'HackerRank', cat: 'Developer', emoji: '💚',
        url: 'https://www.hackerrank.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'not found'],
    },
    {
        name: 'LeetCode', cat: 'Developer', emoji: '🧩',
        url: 'https://leetcode.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', '404'],
        foundStrings: ['user-profile', 'username-info'],
    },
    {
        name: 'Kaggle', cat: 'Developer', emoji: '📊',
        url: 'https://www.kaggle.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found'],
    },
    {
        name: 'FreeCodeCamp', cat: 'Developer', emoji: '🔥',
        url: 'https://www.freecodecamp.org/news/author/{u}',
        notFoundOn: [404],
        notFoundStrings: ['ghost: unknown member', 'member not found'],
    },
    {
        name: 'CodeSandbox', cat: 'Developer', emoji: '📁',
        url: 'https://codesandbox.io/u/{u}',
        notFoundOn: [404],
        notFoundStrings: ['user not found', '404'],
    },

    // ── Social ─────────────────────────────────────────────────────────────────
    {
        // Reddit's JSON API endpoint returns 404 for nonexistent users — reliable
        name: 'Reddit', cat: 'Social', emoji: '🟠',
        url: 'https://www.reddit.com/user/{u}/about.json',
        notFoundOn: [404],
        notFoundStrings: ['"error":', '"reason":"NOT_FOUND"'],
        foundStrings: ['"name":"'],
    },
    {
        name: 'TikTok', cat: 'Social', emoji: '🎵',
        url: 'https://www.tiktok.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ["couldn't find this account", 'user-not-found', 'this account is private'],
        foundStrings: ['og:title', 'tiktok-user'],
    },
    {
        name: 'Pinterest', cat: 'Social', emoji: '📌',
        url: 'https://www.pinterest.com/{u}/',
        notFoundOn: [404],
        notFoundStrings: ["sorry! we couldn't find that page", 'page not found'],
        foundStrings: ['profileCard', 'og:image'],
    },
    {
        name: 'Threads', cat: 'Social', emoji: '🧵',
        url: 'https://www.threads.net/@{u}',
        notFoundOn: [404],
        notFoundStrings: ["sorry, this page isn't available", 'page not found'],
    },
    {
        name: 'Instagram', cat: 'Social', emoji: '📸',
        url: 'https://www.instagram.com/{u}/',
        notFoundOn: [404],
        blockedOn: [403, 429, 503],
        notFoundStrings: ["sorry, this page isn't available"],
    },
    {
        name: 'X (Twitter)', cat: 'Social', emoji: '𝕏',
        url: 'https://x.com/{u}',
        notFoundOn: [404],
        blockedOn: [403, 429],
        notFoundStrings: ["this account doesn't exist", 'user not found'],
    },
    {
        name: 'Facebook', cat: 'Social', emoji: '📘',
        url: 'https://www.facebook.com/{u}',
        notFoundOn: [404],
        blockedOn: [403, 429, 500],
        notFoundStrings: ["this page isn't available", 'page you requested cannot'],
    },
    {
        name: 'Snapchat', cat: 'Social', emoji: '👻',
        url: 'https://www.snapchat.com/add/{u}',
        notFoundOn: [404],
        notFoundStrings: ['sorry!', 'page not found', 'could not be found'],
        foundStrings: ['snapcode', 'bitmoji'],
    },

    // ── Professional ───────────────────────────────────────────────────────────
    {
        name: 'LinkedIn', cat: 'Professional', emoji: '💼',
        url: 'https://www.linkedin.com/in/{u}',
        notFoundOn: [404],
        blockedOn: [999, 403, 429],
        notFoundStrings: ['page not found', 'this profile is not available'],
    },
    {
        name: 'AngelList', cat: 'Professional', emoji: '😇',
        url: 'https://angel.co/u/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found'],
        foundStrings: ['angellist', 'u-name'],
    },
    {
        name: 'ResearchGate', cat: 'Professional', emoji: '🔬',
        url: 'https://www.researchgate.net/profile/{u}',
        notFoundOn: [404],
        notFoundStrings: ["doesn't exist", 'profile not found', 'http error 404'],
    },
    {
        name: 'ORCID', cat: 'Professional', emoji: '🆔',
        url: 'https://orcid.org/{u}',
        notFoundOn: [404],
        notFoundStrings: ['we were unable to find the orcid', '404'],
    },

    // ── Content Creation ───────────────────────────────────────────────────────
    {
        name: 'YouTube', cat: 'Content', emoji: '▶️',
        url: 'https://www.youtube.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ["this page isn't available", '404 error'],
        foundStrings: ['channelMetadataRenderer', 'og:title'],
    },
    {
        name: 'Twitch', cat: 'Content', emoji: '💜',
        url: 'https://www.twitch.tv/{u}',
        notFoundOn: [404],
        notFoundStrings: ["unless you've got a time machine", '404'],
        foundStrings: ['og:image', 'channel'],
    },
    {
        name: 'Medium', cat: 'Content', emoji: '✍️',
        url: 'https://medium.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'memberships and publications'],
        foundStrings: ['postMetaLockup', 'member-card', 'og:type'],
    },
    {
        // Substack subdomain — always returns 200; MUST check body
        name: 'Substack', cat: 'Content', emoji: '📧',
        url: 'https://{u}.substack.com',
        notFoundOn: [404],
        notFoundStrings: [
            'is not a substack', 'this publication does not exist',
            'publication not found', 'no publication found',
            'http error 404', 'page-not-found', 'site not found',
        ],
        foundStrings: ['substack-publication', '<meta name="description"', 'og:site_name'],
        mustConfirm: true,
    },
    {
        name: 'SoundCloud', cat: 'Content', emoji: '🎧',
        url: 'https://soundcloud.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ["we can't find that user", '404'],
        foundStrings: ['sc-link-dark', 'soundcloud-user', 'og:title'],
    },
    {
        name: 'Spotify', cat: 'Content', emoji: '🟢',
        url: 'https://open.spotify.com/user/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'spotify – page not found'],
        foundStrings: ['user-page', 'og:title'],
    },

    // ── Gaming ─────────────────────────────────────────────────────────────────
    {
        name: 'Steam', cat: 'Gaming', emoji: '🎮',
        url: 'https://steamcommunity.com/id/{u}',
        notFoundOn: [404],
        notFoundStrings: ['the specified profile could not be found', 'profile_private_age'],
        foundStrings: ['class="persona_name"', 'class="profile_header"'],
    },
    {
        name: 'Epic Games', cat: 'Gaming', emoji: '⚡',
        url: 'https://store.epicgames.com/en-US/u/{u}',
        notFoundOn: [404],
        notFoundStrings: ['user not found', 'page not found'],
    },
    {
        name: 'PSN Profiles', cat: 'Gaming', emoji: '🎯',
        url: 'https://psnprofiles.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['psn id not found', 'user not found', 'does not exist'],
        foundStrings: ['class="username"', 'psnprofiles'],
    },

    // ── Design ─────────────────────────────────────────────────────────────────
    {
        name: 'Dribbble', cat: 'Design', emoji: '🏀',
        url: 'https://dribbble.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ["whoops", "page you're looking for can't be found"],
        foundStrings: ['masthead-username', 'card-subject'],
    },
    {
        name: 'Behance', cat: 'Design', emoji: '🎨',
        url: 'https://www.behance.net/{u}',
        notFoundOn: [404],
        notFoundStrings: ["this page doesn't exist", '404'],
        foundStrings: ['ProfileInfo', 'UserInfo', 'og:title'],
    },
    {
        name: 'ArtStation', cat: 'Design', emoji: '🖌️',
        url: 'https://www.artstation.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ["page not found", "we can't find that page"],
        foundStrings: ['portfolio-user-full-name', 'ng-scope'],
    },

    // ── Forum & Community ──────────────────────────────────────────────────────
    {
        name: 'Quora', cat: 'Forum', emoji: '❓',
        url: 'https://www.quora.com/profile/{u}',
        notFoundOn: [404],
        blockedOn: [403, 429, 503],
        notFoundStrings: ["page not found", "we couldn't find", 'does not exist'],
    },
    {
        name: 'ProductHunt', cat: 'Forum', emoji: '🚀',
        url: 'https://www.producthunt.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ['not found', '404'],
        foundStrings: ['user-profile', 'og:title'],
    },
    {
        name: 'Hashnode', cat: 'Forum', emoji: '🔷',
        url: 'https://hashnode.com/@{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'uh-oh', '404'],
        foundStrings: ['hashnode-user', 'profile-image'],
    },
    {
        name: 'Disqus', cat: 'Forum', emoji: '💬',
        url: 'https://disqus.com/by/{u}/',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'not found'],
        foundStrings: ['profile-nav', 'avatar'],
    },

    // ── Blogging ───────────────────────────────────────────────────────────────
    {
        // WordPress subdomain: returns 200 for missing blogs — must confirm
        name: 'WordPress', cat: 'Blog', emoji: '🔵',
        url: 'https://{u}.wordpress.com',
        notFoundOn: [404],
        notFoundStrings: [
            "doesn't exist", 'do you want to register',
            'wordpress.com/new', 'this site does not exist',
            'site not found', 'no site with that address',
        ],
        foundStrings: ['class="wp-', 'og:site_name'],
        mustConfirm: true,
    },
    {
        // Blogspot subdomain — can return 200 for missing blogs
        name: 'Blogger', cat: 'Blog', emoji: '📝',
        url: 'https://{u}.blogspot.com',
        notFoundOn: [404],
        notFoundStrings: ['blog not found', 'sorry, the blog', '404'],
        mustConfirm: true,
    },
    {
        // Ghost.io subdomain — must confirm via body
        name: 'Ghost', cat: 'Blog', emoji: '👁️',
        url: 'https://{u}.ghost.io',
        notFoundOn: [404],
        notFoundStrings: ['page not found', '404', 'ghost: unknown member', 'site not found'],
        mustConfirm: true,
    },

    // ── OSINT Extras ───────────────────────────────────────────────────────────
    {
        name: 'Gravatar', cat: 'OSINT', emoji: '🌐',
        url: 'https://en.gravatar.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'does not exist'],
        foundStrings: ['gravatar-header', 'entry-title'],
    },
    {
        name: 'About.me', cat: 'OSINT', emoji: 'ℹ️',
        url: 'https://about.me/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'user not found'],
        foundStrings: ['profile-content', 'about-me'],
    },
    {
        name: 'Keybase', cat: 'OSINT', emoji: '🔑',
        url: 'https://keybase.io/{u}',
        notFoundOn: [404],
        notFoundStrings: ['not found', 'has no user page'],
        foundStrings: ['keybase-username'],
    },
    {
        name: 'BuyMeACoffee', cat: 'OSINT', emoji: '☕',
        url: 'https://www.buymeacoffee.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ["page not found", "doesn't exist"],
        foundStrings: ['creator-page', 'bmc-btn'],
    },
    {
        name: 'Patreon', cat: 'OSINT', emoji: '🎁',
        url: 'https://www.patreon.com/{u}',
        notFoundOn: [404],
        notFoundStrings: ['page not found', 'does not have a patreon'],
        foundStrings: ['creator-page', 'patreon-nav'],
    },
];

// ─── BROWSER-LIKE HEADERS ────────────────────────────────────
const BROWSER_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Cache-Control': 'no-cache',
    'Pragma': 'no-cache',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Upgrade-Insecure-Requests': '1',
};

function buildUrl(pattern, username) {
    return pattern.replace(/{u}/g, encodeURIComponent(username));
}

// ─── SCAN ENGINE — SMART DETECTION ───────────────────────────
async function checkPlatform(platform, username) {
    const url = buildUrl(platform.url, username);
    const t0 = Date.now();

    try {
        const resp = await axios.get(url, {
            headers: BROWSER_HEADERS,
            timeout: 12000,
            maxRedirects: 5,
            validateStatus: () => true,   // never throw on HTTP errors
            responseType: 'text',
        });

        const ms = Date.now() - t0;
        const status = resp.status;
        const body = typeof resp.data === 'string' ? resp.data.toLowerCase() : '';

        // ── 1. Blocked status codes ──────────────────────────────
        const blockedCodes = platform.blockedOn || [403, 429, 503, 999];
        if (blockedCodes.includes(status)) {
            return { ...platform, url, status: 'BLOCKED', httpStatus: status, ms };
        }

        // ── 2. HTTP not-found codes ──────────────────────────────
        const notFoundCodes = platform.notFoundOn || [404];
        if (notFoundCodes.includes(status)) {
            return { ...platform, url, status: 'NOT_FOUND', httpStatus: status, ms };
        }

        // ── 3. StackOverflow — JSON items exact match ────────────
        if (platform.jsonItemsCheck) {
            try {
                const json = JSON.parse(resp.data);
                const items = json.items || [];
                const match = items.find(i =>
                    i.display_name?.toLowerCase() === username.toLowerCase()
                );
                if (match) {
                    const profileUrl = `https://stackoverflow.com/users/${match.user_id}/${match.display_name}`;
                    return { ...platform, url: profileUrl, status: 'FOUND', httpStatus: status, ms };
                }
                return { ...platform, url, status: 'NOT_FOUND', httpStatus: status, ms };
            } catch {
                return { ...platform, url, status: 'UNCERTAIN', httpStatus: status, ms };
            }
        }

        // ── 4. Body-based NOT FOUND patterns ────────────────────
        const notFoundStrings = platform.notFoundStrings || [];
        const isNotFound = notFoundStrings.some(s => body.includes(s.toLowerCase()));
        if (isNotFound) {
            return { ...platform, url, status: 'NOT_FOUND', httpStatus: status, ms };
        }

        // ── 5. Positive confirmation via foundStrings ────────────
        const foundStrings = platform.foundStrings || [];
        const isConfirmed = foundStrings.length > 0 &&
            foundStrings.some(s => body.includes(s.toLowerCase()));

        if (status === 200) {
            if (isConfirmed) {
                return { ...platform, url, status: 'FOUND', httpStatus: status, ms };
            }
            // No positive patterns found on page
            if (platform.mustConfirm) {
                // We cannot reliably confirm — return UNCERTAIN so user can verify
                return { ...platform, url, status: 'UNCERTAIN', httpStatus: status, ms };
            }
            if (foundStrings.length === 0) {
                // Platform has no foundStrings defined: trust the 200
                return { ...platform, url, status: 'FOUND', httpStatus: status, ms };
            }
            // Has foundStrings but none matched — could be blocked or nonexistent
            return { ...platform, url, status: 'UNCERTAIN', httpStatus: status, ms };
        }

        // ── 6. Unexpected status (3xx unresolved, 5xx, etc.) ────
        return { ...platform, url, status: 'BLOCKED', httpStatus: status, ms };

    } catch (err) {
        const ms = Date.now() - t0;
        if (axios.isCancel(err) || err.code === 'ECONNABORTED' || err.code === 'ETIMEDOUT') {
            return { ...platform, url, status: 'BLOCKED', httpStatus: null, ms, error: 'Timeout' };
        }
        const httpStatus = err.response?.status || null;
        const notFoundCodes = platform.notFoundOn || [404];
        if (httpStatus && notFoundCodes.includes(httpStatus)) {
            return { ...platform, url, status: 'NOT_FOUND', httpStatus, ms };
        }
        return { ...platform, url, status: 'BLOCKED', httpStatus, ms, error: err.code || err.message };
    }
}

// ─── SSE SCAN ROUTE ───────────────────────────────────────────
app.get('/api/scan/:username', authRequired, async (req, res) => {
    const { username } = req.params;
    if (!username || username.length < 1 || username.length > 50) {
        return res.status(400).json({ error: 'Invalid username' });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();

    const send = (event, data) => {
        res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        if (res.flush) res.flush();
    };

    send('start', { total: PLATFORMS.length, username });

    const BATCH = 8;
    let done = 0;

    for (let i = 0; i < PLATFORMS.length; i += BATCH) {
        if (req.destroyed) break;
        const batch = PLATFORMS.slice(i, Math.min(i + BATCH, PLATFORMS.length));

        const results = await Promise.allSettled(
            batch.map(p => checkPlatform(p, username))
        );

        results.forEach((r, bi) => {
            done++;
            const platform = batch[bi];
            const result = (r.status === 'fulfilled' && r.value)
                ? r.value
                : { ...platform, url: buildUrl(platform.url, username), status: 'BLOCKED', ms: 0 };
            send('result', { ...result, done, total: PLATFORMS.length });
        });

        await new Promise(resolve => setTimeout(resolve, 100));
    }

    send('complete', { done, total: PLATFORMS.length });
    res.end();
});

// ─── HEALTH CHECK ────────────────────────────────────────────
app.get('/api/health', (req, res) => res.json({ status: 'ok', time: new Date().toISOString() }));

// ─── START ───────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log(`\n🔍 OSINT Recon Engine running on http://localhost:${PORT}`);
    console.log(`   Auth: POST /api/auth/register | POST /api/auth/login`);
    console.log(`   Scan: GET  /api/scan/:username (SSE, requires JWT)\n`);
    console.log(`   Detection: HTTP codes + body content analysis + UNCERTAIN for ambiguous\n`);
});
