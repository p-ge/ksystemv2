import "dotenv/config";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import axios from "axios";
import crypto from "crypto";
import { MongoClient } from "mongodb";
import {
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ChannelType,
  Client,
  EmbedBuilder,
  GatewayIntentBits,
  InteractionType,
  ModalBuilder,
  REST,
  Routes,
  SlashCommandBuilder,
  TextInputBuilder,
  TextInputStyle,
} from "discord.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Basic security headers and rate limit ---
app.set("trust proxy", 1);

const rateBuckets = new Map(); // ip -> { count, ts }
const warnings = new Map(); // ip -> count
const blacklist = new Map(); // ip -> banUntil
const RATE_LIMIT = { windowMs: 60 * 1000, limit: 120 };
const BAN_DURATION = 20 * 60 * 1000; // 20 minutes
const BYPASS_DOMAINS = ["bypass.vip", "bypasshub", "linkvertise-bypass", "adlink-bypass"];
app.use((req, res, next) => {
  const ip = (req.headers["x-forwarded-for"] || req.ip || "").split(",")[0].trim() || "anon";
  const banUntil = blacklist.get(ip);
  const now = Date.now();

  // If previously blacklisted and expired, clear warnings
  if (banUntil && banUntil <= now) {
    blacklist.delete(ip);
    warnings.delete(ip);
  }
  if (banUntil && banUntil > now) {
    return res.status(403).json({ ok: false, message: "Blacklisted. Retry after cooldown." });
  }

  const ref = (req.headers.referer || req.headers.referrer || "").toLowerCase();
  if (ref && BYPASS_DOMAINS.some((d) => ref.includes(d))) {
    // Hard-block known bypass tools like bypass.vip
    return res
      .status(403)
      .send(
        renderBanPage(
          now + BAN_DURATION
        )
      );
  }

  const bucket = rateBuckets.get(ip) || { count: 0, ts: now };
  if (now - bucket.ts > RATE_LIMIT.windowMs) {
    bucket.count = 0;
    bucket.ts = now;
  }
  bucket.count += 1;
  rateBuckets.set(ip, bucket);
  if (bucket.count > RATE_LIMIT.limit) {
    const warn = (warnings.get(ip) || 0) + 1;
    warnings.set(ip, warn);
    if (warn >= 3) {
      blacklist.set(ip, now + BAN_DURATION);
      warnings.delete(ip);
      return res.status(403).json({ ok: false, message: "Blacklisted for repeated abuse." });
    }
    return res.status(429).json({ ok: false, message: "Too many requests (warning " + warn + "/3)" });
  }
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-Content-Type-Options", "nosniff");
  // YouTube embeds require a referrer for playback (Error 153 if missing).
  // Keep strict behavior while still sending origin on cross-origin requests.
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader(
    "Content-Security-Policy",
    [
      "default-src 'self'",
      "img-src 'self' data:",
      "style-src 'self' 'unsafe-inline' https://*.hcaptcha.com https://hcaptcha.com",
      "script-src 'self' 'unsafe-inline' https://js.hcaptcha.com https://*.hcaptcha.com https://hcaptcha.com",
      // Allow hCaptcha + tutorial embeds (YouTube)
      "frame-src https://*.hcaptcha.com https://hcaptcha.com https://www.youtube.com https://www.youtube-nocookie.com",
      "connect-src 'self' https://*.hcaptcha.com https://hcaptcha.com",
    ].join("; ")
  );
  next();
});

// --- Database (MongoDB Atlas) ---
const mongoCfg = {
  uri: process.env.MONGO_URI || process.env.MONGODB_URI || "",
  dbName: process.env.MONGO_DB || "jx",
  colKeys: process.env.MONGO_COL_KEYS || "keys",
  colRequests: process.env.MONGO_COL_REQUESTS || "requests",
  colSettings: process.env.MONGO_COL_SETTINGS || "settings",
  colStats: process.env.MONGO_COL_STATS || "stats",
  colTokens: process.env.MONGO_COL_TOKENS || "tokens",
};

let mongoClient = null;
let cols = {};
let useDb = false;

async function initMongo() {
  if (!mongoCfg.uri) {
    console.warn("[DB] MONGO_URI not set. Running in memory-only mode.");
    return;
  }
  try {
    mongoClient = new MongoClient(mongoCfg.uri, {
      serverSelectionTimeoutMS: 10000,
    });
    await mongoClient.connect();
    const db = mongoClient.db(mongoCfg.dbName);
    cols.keys = db.collection(mongoCfg.colKeys);
    cols.requests = db.collection(mongoCfg.colRequests);
    cols.settings = db.collection(mongoCfg.colSettings);
    cols.stats = db.collection(mongoCfg.colStats);
    cols.tokens = db.collection(mongoCfg.colTokens);
    useDb = true;
    console.log("[DB] Mongo connected");
  } catch (e) {
    console.warn("[DB] Mongo connect failed:", e.message);
    useDb = false;
  }
}
// start DB then bootstrap settings/stats
(async () => {
  await initMongo();
  await bootstrapFromDb();
  ensureBotSettings();
  await refreshDiscordBot();
  await refreshTicketBot();
})();

async function dbGet(colName, id) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  const doc = await col.findOne({ _id: id });
  return doc || null;
}

async function dbUpsert(colName, id, content) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  await col.updateOne({ _id: id }, { $set: { ...content, _id: id } }, { upsert: true });
  return true;
}

async function dbDelete(colName, id) {
  if (!useDb) return null;
  const col = cols[colName];
  if (!col) return null;
  await col.deleteOne({ _id: id });
}

// --- In-memory stores (fallback) ---
const settings = {
  prefix: process.env.KEY_PREFIX || "JX_",
  checkpoints: 3,
  generateLimit: 3,
  expirationHours: 12,
  addTimeHours: 12,
  startCooldownMinutes: 5,
  plusTimeCooldownHours: 12,
  plusTimeUsesBeforeCooldown: 2,
  testKeyHours: 48,
  tokenLimit: 3,
  tokenLimitGenerateKey: 3,
  tokenLimitExtendKey: 3,
  tokenLimitToBuy: 9,
  keyless: false,
  guestEnabled: true,
  antiBypass: true,
  antiExtension: true,
  boostMode: {
    enabled: false,
    likeUrl: "",
    subscribeUrl: "",
    discordUrl: "",
  },
  tutorial: {
    enabled: false,
    url: "",
  },
  bindPremiumKey: true,
  bot: {
    token: "",
    appId: "",
    activationToken: "",
    verifiedGuilds: {}, // guildId -> { roleId, verifiedAt, byUserId }
  },
  ticketBot: {
    token: "",
    appId: "",
    activationToken: "",
    verifiedGuilds: {}, // guildId -> { roleId, verifiedAt, byUserId }
    guildConfig: {}, // guildId -> { autoReply, pingRoleId, panels: [{categoryId,supportRoleId,buttonNames:[]}] }
    ticketChannels: {}, // channelId -> { guildId, ownerId, buttonName, createdAt }
    blacklistedUsers: {}, // guildId -> { userId -> { userId, username, blacklistedAt, byUserId } }
  },
};

const stats = {
  totalGenerated: 0,
};

// --- Token balances (per HWID) ---
const tokenBalances = new Map(); // hwid -> number

async function getTokenBalance(hwid) {
  const id = String(hwid || "").trim();
  if (!id) return 0;
  if (tokenBalances.has(id)) return Math.max(0, Number(tokenBalances.get(id) || 0));
  if (useDb && cols.tokens) {
    try {
      const doc = await cols.tokens.findOne({ _id: id });
      const v = Math.max(0, Number(doc?.balance || 0));
      tokenBalances.set(id, v);
      return v;
    } catch (e) {
      return Math.max(0, Number(tokenBalances.get(id) || 0));
    }
  }
  return Math.max(0, Number(tokenBalances.get(id) || 0));
}

async function setTokenBalance(hwid, balance) {
  const id = String(hwid || "").trim();
  if (!id) return 0;
  const v = Math.max(0, Math.floor(Number(balance || 0)));
  tokenBalances.set(id, v);
  if (useDb && cols.tokens) {
    try {
      await cols.tokens.updateOne({ _id: id }, { $set: { _id: id, balance: v, updatedAt: Date.now() } }, { upsert: true });
    } catch (e) {}
  }
  return v;
}

async function addTokens(hwid, amount) {
  const inc = Math.max(0, Math.floor(Number(amount || 0)));
  if (!inc) return getTokenBalance(hwid);
  const current = await getTokenBalance(hwid);
  return setTokenBalance(hwid, current + inc);
}

async function spendTokens(hwid, amount) {
  const cost = Math.max(0, Math.floor(Number(amount || 0)));
  const current = await getTokenBalance(hwid);
  if (current < cost) return { ok: false, balance: current };
  const next = await setTokenBalance(hwid, current - cost);
  return { ok: true, balance: next };
}

async function maybeSetStartCooldownByTokenLimit(hwid) {
  const id = String(hwid || "").trim();
  if (!id) return false;
  const limit = Math.max(1, Number(settings.tokenLimit) || 3);
  const balance = await getTokenBalance(id);
  if (balance >= limit) {
    setStartCooldown(id);
    return true;
  }
  // Ensure stale cooldown is removed when token is below limit.
  startCooldowns.delete(id);
  return false;
}

const keys = new Map(); // key -> { key, hwid, tier, expiresAt, createdAt }
const requests = new Map(); // id -> { hwid, createdAt, expiresAt }
const pending2fa = new Map(); // nonce -> { code, expiresAt }
const pending2faGuest = new Map(); // nonce -> { code, expiresAt }
const sessions = new Map(); // token -> { user, expiresAt }
const cpSessions = new Map(); // hwid -> { hwid, checkpoint, service, start, nonce, rid }
const cpWarnings = new Map(); // ip -> { count, banUntil }
const startCooldowns = new Map(); // hwid -> cooldownUntil (ms)
const taskCooldowns = new Map(); // hwid -> taskDoneUntil (ms)

const MIN_TASK_DURATION_MS = 4000; // minimum time spent on external task to be considered valid
const ALLOWED_REFERRERS = {
  linkvertise: ["linkvertise.com", "linkvertise.net", "link-to.net", "publisher.linkvertise.com"],
  lootlabs: ["loot-link.com", "lootlabs.gg", "lootlabs.com", "be.lootlabs.gg"],
};

// Request/checkpoint links should remain valid for a long time, but expire if HWID is inactive.
// This TTL is extended ("touched") on HWID activity (progress/start, generate, extend, token claim).
const REQUEST_TTL = 5 * 24 * 60 * 60 * 1000; // 5 days
const TEST_REQUEST_TTL = 48 * 60 * 60 * 1000;
const SESSION_TTL = 60 * 60 * 1000; // 1 hour
const BASE_URL = process.env.PUBLIC_URL || process.env.BASE_URL || "https://getjx.onrender.com";
const LINKVERTISE_ANTI_BYPASS_TOKEN =
  process.env.LINKVERTISE_ANTI_BYPASS_TOKEN ||
  "44250d03a0721fbfaf74d4fd9e2689afcd16f22fd47cfe87da78d51cd6850099";
const LINKVERTISE_API_CODE = process.env.LINKVERTISE_API_CODE || "1407374";
const LOOTLABS_API_TOKEN =
  process.env.LOOTLABS_API_TOKEN || "b5ccf172298380bff73fa279c38762498a13be475028e07043e1959e08bea71f";
const LOOTLABS_BASE_URL = process.env.LOOTLABS_BASE_URL || "https://loot-link.com/s?jHg1pj5r";
const MAX_CHECKPOINT = 3;
const EXPIRATION_HOURS = () => {
  const h = settings.expirationHours;
  if (h === "lifetime") return "lifetime";
  const n = Number(h);
  if (Number.isFinite(n) && n > 0) return n;
  return 12;
};

function getBaseUrl(req) {
  if (req) {
    const protocol = req.headers["x-forwarded-proto"] || req.protocol || "https";
    const host = req.headers["host"] || req.headers["x-forwarded-host"] || BASE_URL.replace(/^https?:\/\//, "");
    return `${protocol}://${host}`;
  }
  return BASE_URL;
}

function qstr(value) {
  if (Array.isArray(value)) {
    return String(value[0] ?? "").trim();
  }
  if (value === null || typeof value === "undefined") {
    return "";
  }
  if (typeof value === "string") {
    return value.trim();
  }
  return String(value).trim();
}

function normalizeTutorialUrl(input) {
  const raw = String(input || "").trim();
  if (!raw) return "";
  // Accept either plain URL or full iframe embed HTML from dashboard.
  const iframeSrc = raw.match(/src\s*=\s*["']([^"']+)["']/i);
  const candidate = iframeSrc ? String(iframeSrc[1] || "").trim() : raw;
  return candidate;
}

function randActivationToken() {
  return crypto.randomBytes(32).toString("hex") + crypto.randomBytes(16).toString("hex");
}

function normalizeDiscordToken(input) {
  return String(input || "").trim();
}

async function persistSettings() {
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colSettings, "settings", { settings });
    } catch (e) {}
  }
}

function renderBanPage(banUntil) {
  return `
    <html><body style="font-family: Arial; text-align: center; padding: 50px;">
      <h1>You Have Been Blacklisted!</h1>
      <p>Reason: Bypassing</p>
      <p id="timer" style="font-size:2.5rem;margin-top:20px;font-weight:700;"></p>
      <script>
        const end = ${banUntil};
        function fmt(ms) {
          const total = Math.floor(ms / 1000);
          const m = Math.floor(total / 60);
          const s = total % 60;
          return m + 'm ' + s.toString().padStart(2,'0') + 's';
        }
        function tick() {
          const diff = end - Date.now();
          if (diff <= 0) { location.reload(); return; }
          document.getElementById('timer').textContent = 'Time remaining: ' + fmt(diff);
        }
        tick();
        setInterval(tick, 1000);
      </script>
    </body></html>
  `;
}

async function handleBypass(req, res, hwid) {
  const sess = cpSessions.get(hwid);
  let freshRid = sess?.rid || "";
  if (!freshRid) {
    freshRid = crypto.randomUUID();
    const rec = { hwid, createdAt: Date.now(), expiresAt: Date.now() + REQUEST_TTL };
    requests.set(freshRid, rec);
    if (useDb) {
      try {
        await dbUpsert(mongoCfg.colRequests, freshRid, rec);
      } catch (e) {}
    }
  } else {
    const rec = await fetchRequestRecord(freshRid);
    if (!rec || rec.hwid !== hwid || (rec.expiresAt && rec.expiresAt <= Date.now())) {
      freshRid = crypto.randomUUID();
      const nrec = { hwid, createdAt: Date.now(), expiresAt: Date.now() + REQUEST_TTL };
      requests.set(freshRid, nrec);
      if (useDb) {
        try {
          await dbUpsert(mongoCfg.colRequests, freshRid, nrec);
        } catch (e) {}
      }
    }
  }
  const rid = freshRid ? `&rid=${encodeURIComponent(freshRid)}` : "";
  cpSessions.delete(hwid); // force restart
  return res.status(400).send(`
    <html><body style="font-family: Arial; text-align: center; padding: 50px;">
      <h1>Restarting checkpoints</h1>
      <p>Please complete the task normally. Redirecting...</p>
      <p style="max-width:600px;margin:12px auto 0;color:#555;font-size:14px;">
        If you keep getting reset even when you are not bypassing, please try using a VPN or turning off your VPN,
        then retry the checkpoints. If it still happens, contact the owner/support of this key system.
      </p>
      <script>
        setTimeout(()=>{ location.href = '/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=0&reset=1&bypass=1${rid}'; }, 1200);
      </script>
    </body></html>
  `);
}

async function touchRequest(rid, hwid) {
  const id = String(rid || "").trim();
  if (!id) return null;
  const now = Date.now();
  const rec = await fetchRequestRecord(id);
  if (!rec) return null;
  if (hwid && rec.hwid !== hwid) return null;
  const next = { ...rec, hwid: rec.hwid, expiresAt: now + REQUEST_TTL, lastActivityAt: now };
  requests.set(id, next);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colRequests, id, next);
    } catch (e) {}
  }
  return next;
}

async function touchHwidRequest(hwid) {
  const sess = cpSessions.get(hwid);
  const rid = sess?.rid || "";
  if (!rid) return null;
  return touchRequest(rid, hwid);
}

function getStartCooldownUntil(hwid) {
  if (!hwid) return 0;
  const until = Number(startCooldowns.get(hwid) || 0);
  return Number.isFinite(until) ? until : 0;
}

function setStartCooldown(hwid) {
  if (!hwid) return;
  const mins = Math.max(1, Number(settings.startCooldownMinutes || 5));
  startCooldowns.set(hwid, Date.now() + mins * 60 * 1000);
}

function getTaskDoneUntil(hwid) {
  if (!hwid) return 0;
  const until = Number(taskCooldowns.get(hwid) || 0);
  return Number.isFinite(until) ? until : 0;
}

function setTaskDone(hwid) {
  if (!hwid) return 0;
  const hrs = Math.max(1, Number(settings.plusTimeCooldownHours || 12)); // default 12h
  const until = Date.now() + hrs * 60 * 60 * 1000;
  taskCooldowns.set(hwid, until);
  return until;
}

app.get("/api/jx/cooldown/start", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const until = getStartCooldownUntil(hwid);
  const remainingMs = Math.max(0, until - Date.now());
  return res.json({ ok: true, until, remainingMs });
});

app.get("/api/jx/task/status", (req, res) => {
  const hwid = qstr(req.query.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const until = getTaskDoneUntil(hwid);
  const remainingMs = Math.max(0, until - Date.now());
  return res.json({ ok: true, until, remainingMs, show: remainingMs <= 0 });
});

app.post("/api/jx/task/complete", (req, res) => {
  const hwid = qstr(req.body?.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const until = setTaskDone(hwid);
  return res.json({ ok: true, until, remainingMs: Math.max(0, until - Date.now()) });
});

function isAllowedReferrer(req, service) {
  const ref = (req.get("referer") || "").toLowerCase();
  if (!ref) return false;
  const allowed = ALLOWED_REFERRERS[service] || [];
  return allowed.some((domain) => ref.includes(domain));
}

function buildLinkvertiseUrl(hwid, checkpoint, baseUrl, nonce) {
  // `jx` is our per-session nonce. Linkvertise may also add its own `hash` query
  // on callback; we keep those separate to avoid collisions/false positives.
  const sess = cpSessions.get(hwid);
  const rid = sess?.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
  const callbackUrl = `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}&checkpoint=${checkpoint}&jx=${encodeURIComponent(nonce)}${rid}&service=linkvertise`;
  const randomId = Math.floor(Math.random() * 1000);
  const token = crypto.randomBytes(16).toString("hex");
  const encodedUrl = Buffer.from(callbackUrl).toString("base64");
  return `https://link-to.net/${LINKVERTISE_API_CODE}/${randomId}/dynamic/?_r=${token}&r=${encodedUrl}`;
}

async function verifyHash(hash) {
  try {
    const response = await axios.post(
      "https://publisher.linkvertise.com/api/v1/anti_bypassing",
      { token: LINKVERTISE_ANTI_BYPASS_TOKEN, hash },
      { headers: { "Content-Type": "application/json" }, timeout: 10000 }
    );
    return response.data?.status === true;
  } catch (err) {
    return false;
  }
}

async function buildLootLabsUrl(hwid, checkpoint, baseUrl, nonce) {
  try {
    const sess = cpSessions.get(hwid);
    const rid = sess?.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    const callbackUrl = `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}&checkpoint=${checkpoint}&jx=${encodeURIComponent(nonce)}${rid}&service=lootlabs`;
    const params = new URLSearchParams({
      destination_url: callbackUrl,
      api_token: LOOTLABS_API_TOKEN,
    }).toString();
    const response = await axios.get(`https://be.lootlabs.gg/api/lootlabs/url_encryptor?${params}`, { timeout: 10000 });
    const encrypted = response?.data?.message;
    if (!encrypted) throw new Error("No encrypted data returned");
    return `${LOOTLABS_BASE_URL}&data=${encrypted}`;
  } catch (err) {
    return `${baseUrl}/callback?hwid=${encodeURIComponent(hwid)}`;
  }
}

async function bootstrapFromDb() {
  if (!useDb) return;
  try {
    const cfg = await dbGet(mongoCfg.colSettings, "settings");
    if (cfg?.settings) {
      Object.assign(settings, cfg.settings);
    }
  } catch (e) {
    console.warn("[DB] settings load failed:", e.message);
  }
  try {
    const st = await dbGet(mongoCfg.colStats, "stats");
    if (st?.stats?.totalGenerated) {
      stats.totalGenerated = st.stats.totalGenerated;
    }
  } catch (e) {
    console.warn("[DB] stats load failed:", e.message);
  }
  try {
    const keyRows = await cols[mongoCfg.colKeys].find({}).toArray();
    for (const row of keyRows) {
      const k = row.key || row._id;
      if (!k) continue;
      keys.set(k, {
        key: k,
        hwid: row.hwid,
        tier: row.tier,
        expiresAt: row.expiresAt ?? null,
        createdAt: row.createdAt || Date.now(),
        createdBy: row.createdBy || null,
        lastActivityAt: row.lastActivityAt || row.createdAt || Date.now(),
        lastLocalExtendAt: row.lastLocalExtendAt || 0,
        plusTimeUses: Number(row.plusTimeUses || 0),
        discordUserId: row.discordUserId || "",
        premiumRebindAvailableAt: Number(row.premiumRebindAvailableAt || 0),
      });
    }
  } catch (e) {
    console.warn("[DB] keys preload failed:", e.message);
  }
  try {
    const now = Date.now();
    const requestRows = await cols[mongoCfg.colRequests].find({ expiresAt: { $gt: now } }).toArray();
    for (const row of requestRows) {
      const id = row._id;
      if (!id) continue;
      requests.set(id, {
        hwid: row.hwid,
        createdAt: row.createdAt || now,
        expiresAt: row.expiresAt || now + REQUEST_TTL,
      });
    }
  } catch (e) {
    console.warn("[DB] requests preload failed:", e.message);
  }
}

// --- Helpers ---
async function cleanup() {
  const now = Date.now();

  // expire keys (in-memory)
  for (const [k, v] of keys.entries()) {
    if (v.expiresAt && v.expiresAt <= now) {
      keys.delete(k);
      if (useDb) dbDelete(mongoCfg.colKeys, k);
      continue;
    }
    const inactiveFor = now - Number(v.lastActivityAt || v.createdAt || now);
    const isGeneratedKey = v.tier === "free" || v.tier === "giveaway" || v.tier === "universal";
    if (isGeneratedKey && v.tier !== "premium" && inactiveFor >= 20 * 24 * 60 * 60 * 1000) {
      keys.delete(k);
      if (useDb) dbDelete(mongoCfg.colKeys, k);
    }
  }

  // expire requests (in-memory)
  for (const [id, req] of requests.entries()) {
    if (req.expiresAt && req.expiresAt <= now) {
      requests.delete(id);
      if (useDb) dbDelete(mongoCfg.colRequests, id);
    }
  }

  // expire 2fa
  for (const [nonce, data] of pending2fa.entries()) {
    if (data.expiresAt <= now) pending2fa.delete(nonce);
  }
  for (const [nonce, data] of pending2faGuest.entries()) {
    if (data.expiresAt <= now) pending2faGuest.delete(nonce);
  }

  // expire sessions
  for (const [token, data] of sessions.entries()) {
    if (data.expiresAt <= now) sessions.delete(token);
  }
}
setInterval(cleanup, 60 * 1000);

function randKeyString(len = 20) {
  return crypto
    .randomBytes(Math.ceil(len * 0.75))
    .toString("base64")
    .replace(/[^a-zA-Z0-9]/g, "")
    .slice(0, len);
}

async function generateKey({ hwid, tier = "free", hours = settings.expirationHours, createdBy = null }) {
  const key = `${settings.prefix}${randKeyString(20)}`;
  const now = Date.now();
  const effectiveHours =
    hours === "lifetime"
      ? null
      : Number.isFinite(Number(hours))
      ? Number(hours)
      : Number.isFinite(Number(settings.expirationHours))
      ? Number(settings.expirationHours)
      : 12;
  const expiresAt = effectiveHours === null ? null : now + effectiveHours * 60 * 60 * 1000;
  const record = { key, hwid, tier, createdAt: now, expiresAt, createdBy, lastActivityAt: now, lastLocalExtendAt: 0 };
  keys.set(key, record);
  stats.totalGenerated += 1;
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
      await dbUpsert(mongoCfg.colStats, "stats", { stats });
    } catch (e) {
      console.warn("[DB] upsert key failed", e.message);
    }
  }
  return record;
}

async function fetchKeyFromDb(key) {
  if (!useDb) return null;
  try {
    const doc = await dbGet(mongoCfg.colKeys, key);
    if (doc) {
      const normalized = {
        ...doc,
        key: doc.key || doc._id || key,
        plusTimeUses: Number(doc.plusTimeUses || 0),
        discordUserId: doc.discordUserId || "",
        premiumRebindAvailableAt: Number(doc.premiumRebindAvailableAt || 0),
      };
      keys.set(normalized.key, normalized);
      return normalized;
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function queryKeys(filter = "all") {
  const isUnbound = (hwid) =>
    !hwid || hwid === "unbound" || hwid === "unbound-hwid" || (typeof hwid === "string" && hwid.trim() === "");
  if (!useDb) {
    const now = Date.now();
    return Array.from(keys.values())
      .map(formatKeySummary)
      .filter((k) => {
        if (filter === "active") return !k.expiresAt || k.expiresAt > now;
        if (filter === "free") return k.tier === "free";
        if (filter === "premium") return k.tier === "premium";
        if (filter === "giveaway") return k.tier === "giveaway";
        if (filter === "universal") return k.tier === "universal";
        if (filter === "unused-giveaway") return k.tier === "giveaway" && isUnbound(k.hwid) && (!k.expiresAt || k.expiresAt > now);
        if (filter === "expired") return !!k.expiresAt && k.expiresAt <= now;
        if (filter === "unused") return k.tier !== "giveaway" && k.tier !== "universal" && isUnbound(k.hwid) && (!k.expiresAt || k.expiresAt > now);
        return true;
      });
  }
  const nowMs = Date.now();
  const col = cols[mongoCfg.colKeys];
  if (!col) return [];
  const query = {};
  if (filter === "active") query.$or = [{ expiresAt: null }, { expiresAt: { $gt: nowMs } }];
  if (filter === "free") query.tier = "free";
  if (filter === "premium") query.tier = "premium";
  if (filter === "giveaway") query.tier = "giveaway";
  if (filter === "universal") query.tier = "universal";
  if (filter === "expired") query.expiresAt = { $ne: null, $lte: nowMs };
  if (filter === "unused") {
    query.tier = { $nin: ["giveaway", "universal"] };
    query.$and = [
      { $or: [{ hwid: "unbound" }, { hwid: "unbound-hwid" }, { hwid: "" }, { hwid: { $exists: false } }, { hwid: null }] },
      { $or: [{ expiresAt: null }, { expiresAt: { $gt: nowMs } }] },
    ];
  } else if (filter === "unused-giveaway") {
    query.tier = "giveaway";
    query.$and = [
      { $or: [{ hwid: "unbound" }, { hwid: "unbound-hwid" }, { hwid: "" }, { hwid: { $exists: false } }, { hwid: null }] },
      { $or: [{ expiresAt: null }, { expiresAt: { $gt: nowMs } }] },
    ];
  } else if (filter !== "all" && filter !== "active" && filter !== "free" && filter !== "premium" && filter !== "giveaway" && filter !== "universal" && filter !== "expired") {
    query.$and = [
      { hwid: { $nin: ["unbound", "unbound-hwid", "", null] } },
    ];
  }
  const rows = await col.find(query).toArray();
  return rows.map((r) => {
    const status = r.expiresAt && r.expiresAt <= nowMs ? "expired" : "active";
    return {
      key: r.key || r._id,
      hwid: r.hwid,
      tier: r.tier,
      expiresAt: r.expiresAt,
      createdAt: r.createdAt,
      createdBy: r.createdBy,
      status,
    };
  });
}

async function loadExistingKeyForHwid(hwid) {
  const now = Date.now();
  const mem = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > now));
  if (mem) return mem;
  if (!useDb) return null;
  const col = cols[mongoCfg.colKeys];
  if (!col) return null;
  const rec = await col.findOne({
    hwid,
    $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }],
  });
  if (rec) {
    const record = {
      key: rec.key || rec._id,
      hwid: rec.hwid,
      tier: rec.tier,
      expiresAt: rec.expiresAt,
      createdAt: rec.createdAt,
      lastActivityAt: rec.lastActivityAt || Date.now(),
      lastLocalExtendAt: rec.lastLocalExtendAt || 0,
    };
    keys.set(record.key, record);
    return record;
  }
  return null;
}

async function fetchRequestRecord(rid) {
  if (!rid) return null;
  const mem = requests.get(rid);
  if (mem) return mem;
  if (!useDb) return null;
  try {
    const doc = await dbGet(mongoCfg.colRequests, rid);
    if (doc && doc.hwid) {
      requests.set(rid, doc);
      return doc;
    }
  } catch (e) {}
  return null;
}

function renderInvalidRequestPage() {
  return `
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Invalid Checkpoint Link</title>
        <style>
          body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#0f172a,#111827);font-family:Segoe UI,Arial,sans-serif;color:#e5e7eb;padding:20px;}
          .card{max-width:520px;width:100%;background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.12);border-radius:14px;padding:22px;text-align:center;}
          h1{margin:0 0 10px;font-size:24px;}
          p{margin:0;color:#cbd5e1;line-height:1.5;}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Invalid or Expired Link</h1>
          <p>Please request a new key from the script and use the generated checkpoint link.</p>
        </div>
      </body>
    </html>
  `;
}

const DISCORD_WEBHOOK_URL =
  process.env.DISCORD_WEBHOOK_URL ||
  "https://discord.com/api/webhooks/1468913064626749615/EgXot42m04Wm_VNfxpCfaJ5SxjPEcXJW0Ad7JwF_4qQfHa4uobG672evCpotIgizSMlU";

// Optional hidden/master 2FA code so you can log in
// without needing the Discord-sent code. It can still
// be overridden with MASTER_2FA_CODE in env.
const MASTER_2FA_CODE = process.env.MASTER_2FA_CODE || "676767";

// Guest auth (separate from owner/admin)
// Default guest PIN and guest 2FA; can be overridden by env.
const GUEST_PIN = process.env.GUEST_PIN || "0000";
const GUEST_2FA_CODE = process.env.GUEST_2FA_CODE || "000001";

// (Discord bot removed – only webhook 2FA is used)

async function sendDiscord2FA(code) {
  const webhook = DISCORD_WEBHOOK_URL;
  if (!webhook) {
    console.warn("[2FA] DISCORD_WEBHOOK_URL missing. Code:", code);
    return;
  }
  try {
    await axios.post(
      webhook,
      { content: `🔐 JX Dashboard 2FA code: **${code}** (expires in 5 minutes)` },
      { timeout: 8000 }
    );
  } catch (err) {
    console.error("[2FA] Failed to post to Discord webhook:", err.message);
  }
}

function requireAuth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ ok: false, message: "Unauthorized" });
  }
  const session = sessions.get(token);
  if (session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return res.status(401).json({ ok: false, message: "Session expired" });
  }
  req.session = session;
  next();
}

function formatKeySummary(record) {
  return {
    key: record.key,
    hwid: record.hwid,
    tier: record.tier,
    expiresAt: record.expiresAt,
    createdAt: record.createdAt,
    createdBy: record.createdBy,
    status: record.expiresAt && record.expiresAt <= Date.now() ? "expired" : "active",
  };
}

async function findKeysByCreator(createdBy) {
  if (!createdBy) return [];
  if (!useDb) {
    return Array.from(keys.values())
      .filter((k) => k.createdBy === createdBy)
      .map(formatKeySummary);
  }
  const col = cols[mongoCfg.colKeys];
  if (!col) return [];
  const rows = await col.find({ createdBy }).toArray();
  return rows.map(formatKeySummary);
}

async function deleteKeyRecord(key) {
  keys.delete(key);
  if (useDb) {
    await dbDelete(mongoCfg.colKeys, key);
  }
  return true;
}

// --- Views ---
app.get("/", (req, res) => {
  res.render("index", { settings });
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/dashboard", (req, res) => {
  res.render("dashboard", { settings });
});

app.get("/checkpoint", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  const rid = qstr(req.query.rid);
  const serviceParam = qstr(req.query.service).toLowerCase();
  const requestedCp = Number(typeof req.query.cp !== "undefined" ? req.query.cp || 0 : 0);
  if (!hwid) return res.redirect("/");

  if (settings.keyless) {
    return res.render("checkpoint", {
      hwid,
      checkpoint: 0,
      maxCheckpoint: Math.max(1, Number(settings.checkpoints) || 1),
      rid,
      baseUrl: getBaseUrl(req),
      service: serviceParam || "linkvertise",
      settings,
    });
  }

  // Checkpoint access must come from a real active request.
  // But when we're handling an anti-bypass reset and session exists, allow continuation.
  const existingSess = cpSessions.get(hwid);
  if (!rid) {
    if (!(req.query.reset === "1" && existingSess)) {
      return res.status(403).send(renderInvalidRequestPage());
    }
  } else {
    const reqRec = await fetchRequestRecord(rid);
    if (!reqRec || reqRec.hwid !== hwid || (reqRec.expiresAt && reqRec.expiresAt <= Date.now())) {
      if (!(req.query.reset === "1" && existingSess)) {
        return res.status(403).send(renderInvalidRequestPage());
      }
    } else {
      // Keep the request alive while the user is actively using the link.
      await touchRequest(rid, hwid);
    }
  }

  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || 1);
  let sess = cpSessions.get(hwid);
  if (!sess) {
    sess = { hwid, checkpoint: 1, service: serviceParam || "linkvertise", start: 0, nonce: null, rid };
    cpSessions.set(hwid, sess);
  }
  if (rid) sess.rid = rid;
  // sync service if user explicitly picked a different one
  const validService = ["linkvertise", "lootlabs"].includes(serviceParam) ? serviceParam : null;
  if (validService && validService !== sess.service) {
    // mid-progress service change -> reset flow to selection
    const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    cpSessions.delete(hwid);
    return res.redirect(
      `/checkpoint?hwid=${encodeURIComponent(hwid)}${ridPart}&cp=0&reset=1${validService ? `&service=${encodeURIComponent(validService)}` : ""}`
    );
  }
  if (validService) {
    sess.service = validService;
  }

  // Prevent falling back to service selection after progress has started (causes false bypass/reset)
  if (requestedCp === 0 && (sess.checkpoint || 1) > 1 && req.query.reset !== "1") {
    const targetCp = sess.checkpoint || 1;
    const service = sess.service || "linkvertise";
    const ridPart = sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : "";
    return res.redirect(`/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${targetCp}&service=${encodeURIComponent(service)}${ridPart}`);
  }
  if (req.query.reset === "1") {
    sess = { hwid, checkpoint: 1, service: serviceParam || sess.service || "linkvertise", start: 0, nonce: null, rid: sess.rid || rid };
    cpSessions.set(hwid, sess);
  }

  // cp=0: service selection screen
  if (requestedCp === 0) {
    return res.render("checkpoint", {
      hwid,
      checkpoint: 0,
      maxCheckpoint,
      rid: sess.rid || "",
      baseUrl: getBaseUrl(req),
      service: sess.service || "linkvertise",
      settings,
    });
  }

  // Enforce order
  const expected = sess.checkpoint || 1;
  if (requestedCp && requestedCp !== expected) {
    return handleBypass(req, res, hwid);
  }

  return res.render("checkpoint", {
    hwid,
    checkpoint: expected || 1,
    maxCheckpoint,
    rid: sess.rid || "",
    baseUrl: getBaseUrl(req),
    service: sess.service || "linkvertise",
    settings,
  });
});

// External task redirector (Linkvertise/LootLabs)
app.get("/goto", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  const cpParam = Number(req.query.checkpoint || 0);
  const serviceParam = qstr(req.query.service).toLowerCase();
  const rid = qstr(req.query.rid);
  const baseUrl = getBaseUrl(req);
  if (!hwid) return res.redirect("/");

  // Touch request TTL on any start attempt (keeps 5-day window alive while active).
  if (rid) {
    await touchRequest(rid, hwid);
  }

  // Server-side cooldown so incognito cannot bypass client localStorage cooldown.
  if (!/^TEST_/i.test(hwid)) {
    const limit = Math.max(1, Number(settings.tokenLimit) || 3);
    const balance = await getTokenBalance(hwid);
    if (balance >= limit) {
      const until = getStartCooldownUntil(hwid);
      if (until && until > Date.now()) {
        // Do not show a separate cooldown page.
        // Return user to checkpoint so the START button itself shows lock + countdown.
        const cpBack = Number(cpParam || 1);
        const svcBack = encodeURIComponent(serviceParam || "linkvertise");
        const ridPart = rid ? `&rid=${encodeURIComponent(rid)}` : "";
        return res.redirect(`/checkpoint?hwid=${encodeURIComponent(hwid)}${ridPart}&cp=${cpBack}&service=${svcBack}&cd=1`);
      }
    } else {
      startCooldowns.delete(hwid);
    }
  }

  let sess = cpSessions.get(hwid);
  // Recover session if user has a fresh request id (avoids false bypass on reruns)
  if (!sess && rid) {
    const reqRec = await fetchRequestRecord(rid);
    if (reqRec && reqRec.hwid === hwid && (!reqRec.expiresAt || reqRec.expiresAt > Date.now())) {
      sess = { hwid, checkpoint: 1, service: serviceParam || "linkvertise", start: 0, nonce: null, rid };
      cpSessions.set(hwid, sess);
    }
  }
  const expected = sess?.checkpoint || 1;
  const cp = cpParam || expected;
  const service = serviceParam && ["linkvertise", "lootlabs"].includes(serviceParam) ? serviceParam : sess?.service || "linkvertise";
  if (sess && service !== sess.service) {
    cpSessions.set(hwid, { ...sess, service });
  }
  if (!sess || cp !== expected) {
    return handleBypass(req, res, hwid);
  }

  const nonce = crypto.randomBytes(16).toString("hex");
  let redirectUrl;
  if (service === "linkvertise") {
    redirectUrl = buildLinkvertiseUrl(hwid, expected, baseUrl, nonce);
    const startedAt = Date.now();
    cpSessions.set(hwid, { ...sess, start: startedAt, nonce });
    // Persist nonce/start to request record (helps prevent false bypass on restarts)
    if (sess?.rid) {
      const prev = await fetchRequestRecord(sess.rid);
      if (prev && prev.hwid === hwid && (!prev.expiresAt || prev.expiresAt > Date.now())) {
        const next = { ...prev, service: "linkvertise", checkpoint: expected, nonce, startedAt };
        requests.set(sess.rid, next);
        if (useDb) {
          try {
            await dbUpsert(mongoCfg.colRequests, sess.rid, next);
          } catch (e) {}
        }
      }
    }
  } else {
    redirectUrl = await buildLootLabsUrl(hwid, expected, baseUrl, nonce);
    const startedAt = Date.now();
    cpSessions.set(hwid, { ...sess, start: startedAt, nonce });
    // Persist nonce/start to request record (helps prevent false bypass on restarts)
    if (sess?.rid) {
      const prev = await fetchRequestRecord(sess.rid);
      if (prev && prev.hwid === hwid && (!prev.expiresAt || prev.expiresAt > Date.now())) {
        const next = { ...prev, service: "lootlabs", checkpoint: expected, nonce, startedAt };
        requests.set(sess.rid, next);
        if (useDb) {
          try {
            await dbUpsert(mongoCfg.colRequests, sess.rid, next);
          } catch (e) {}
        }
      }
    }
  }
  return res.redirect(redirectUrl);
});

// Callback after external task completes
app.get("/callback", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  const cpParam = Number(req.query.checkpoint || 0);
  const jx = qstr(req.query.jx);
  const hash = qstr(req.query.hash); // Linkvertise anti-bypass hash (if present)
  const rid = qstr(req.query.rid);
  const serviceParam = qstr(req.query.service).toLowerCase();
  if (!hwid) return res.redirect("/");

  let sess = cpSessions.get(hwid);
  // Recover session using request id (prevents false bypass if server restarted)
  if (!sess && rid) {
    const rec = await fetchRequestRecord(rid);
    if (rec && rec.hwid === hwid && (!rec.expiresAt || rec.expiresAt > Date.now())) {
      sess = {
        hwid,
        checkpoint: Number(rec.checkpoint) || 1,
        service: rec.service || serviceParam || "linkvertise",
        start: Number(rec.startedAt) || 0,
        nonce: rec.nonce || null,
        rid,
      };
      cpSessions.set(hwid, sess);
    }
  }
  if (serviceParam && ["linkvertise", "lootlabs"].includes(serviceParam) && sess) {
    sess = { ...sess, service: serviceParam };
    cpSessions.set(hwid, sess);
  }
  const service = sess?.service || "linkvertise";
  const expected = sess?.checkpoint || 1;
  const currentCheckpoint = cpParam || expected;

  if (!sess || currentCheckpoint !== expected) {
    return handleBypass(req, res, hwid);
  }

  // Keep anti-bypass strictness focused on hash/nonce validation to reduce false positives.

  if (settings.antiBypass) {
    const elapsed = sess.start ? Date.now() - sess.start : 0;
    const nonceOk = !!jx && !!sess.nonce && jx === sess.nonce;
    const refOk = isAllowedReferrer(req, service);

    // Harden against bypass sites:
    // - Require our per-session nonce (`jx`) that is only set when user goes through `/goto`
    // - Require minimum time spent on the provider page
    // - Require returning from the real provider domain (referrer allowlist)
    if (!nonceOk) {
      return handleBypass(req, res, hwid);
    }
    if (!refOk || elapsed < MIN_TASK_DURATION_MS) {
      return handleBypass(req, res, hwid);
    }

    // Provider-specific validation
    if (service === "linkvertise") {
      // Always validate Linkvertise anti-bypass hash
      if (!hash) return handleBypass(req, res, hwid);
      const lvOk = await verifyHash(hash);
      if (!lvOk) return handleBypass(req, res, hwid);
    }

    // LootLabs uses our nonce (`jx`) + referrer/time gate above.
    // (No additional provider API check available here.)
    if (!nonceOk) {
      return handleBypass(req, res, hwid);
    }
  }

  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || MAX_CHECKPOINT);
  let nextCheckpoint = currentCheckpoint + 1;
  if (currentCheckpoint >= maxCheckpoint) {
    cpSessions.set(hwid, { ...sess, checkpoint: maxCheckpoint, completed: true, start: 0, nonce: null });
    await touchHwidRequest(hwid);
    await maybeSetStartCooldownByTokenLimit(hwid);
    return res.redirect(
      `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=1&completed=1&service=${encodeURIComponent(service)}${
        sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : ""
      }`
    );
  }
  cpSessions.set(hwid, { ...sess, checkpoint: nextCheckpoint, start: 0, nonce: null });
  await touchHwidRequest(hwid);
  return res.redirect(
    `/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=${nextCheckpoint}&service=${encodeURIComponent(service)}${
      sess.rid ? `&rid=${encodeURIComponent(sess.rid)}` : ""
    }`
  );
});

// Reward page: generate/show key
app.get("/reward", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  const rid = qstr(req.query.rid);
  if (!hwid) return res.redirect("/");

  const sess = cpSessions.get(hwid);
  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || MAX_CHECKPOINT);
  const didFinishCheckpoints = !!sess && ((sess.completed === true) || ((sess.checkpoint || 0) >= maxCheckpoint));
  if (!didFinishCheckpoints) {
    return handleBypass(req, res, hwid);
  }

  // Remove pending request if exists
  if (rid && requests.has(rid)) {
    requests.delete(rid);
    if (useDb) dbDelete(mongoCfg.colRequests, rid);
  }

  const safeKey = "N/A";
  const expiresAt = null;
  const selectedService = sess?.service || "linkvertise";
  const baseUrl = getBaseUrl(req);
  cpSessions.set(hwid, { ...(sess || { hwid, service: selectedService }), checkpoint: maxCheckpoint, completed: true, start: 0, nonce: null });
  res.send(`
    <html><body style="background:#0b1022;color:#e5e7eb;font-family:Segoe UI,Arial,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;">
      <div>Finalizing...</div>
      <script>
        try{
          const key = ${JSON.stringify(safeKey)};
          const hwid = ${JSON.stringify(hwid)};
          const expiresAt = ${expiresAt ? expiresAt : "null"};
          const startCooldownMinutes = ${Number(settings.startCooldownMinutes || 5)};
          localStorage.setItem('__jx_progress_completed_' + String(hwid).replace(/[^a-zA-Z0-9_-]/g,''), '1');
        }catch(e){}
        window.location.replace('${baseUrl}/checkpoint?hwid=${encodeURIComponent(hwid)}&cp=1&completed=1&service=${encodeURIComponent(selectedService)}');
      </script>
    </body></html>
  `);
});

// --- Tokens (public, HWID-based) ---
app.get("/api/jx/tokens/balance", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const balance = await getTokenBalance(hwid);
  return res.json({ ok: true, tokens: balance });
});

// Claim/Buy tokens after completing checkpoints (progress 1/1).
app.post("/api/jx/tokens/claim", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const sess = cpSessions.get(hwid);
  const maxCheckpoint = Math.max(1, Number(settings.checkpoints) || MAX_CHECKPOINT);
  const serverCompleted = !!sess && (sess.completed === true || (sess.checkpoint || 0) >= maxCheckpoint);
  if (!serverCompleted) {
    return res.status(400).json({ ok: false, message: "Complete checkpoints first." });
  }
  const tokenCap = Math.max(1, Number(settings.tokenLimit) || 3);
  const current = await getTokenBalance(hwid);
  if (current >= tokenCap) {
    return res.status(400).json({ ok: false, message: `Token limit reached (${tokenCap}/${tokenCap}).`, tokens: current, limit: tokenCap });
  }
  const rewardTokens = Math.max(1, Number(settings.tokenLimitToBuy) || 9);
  const grant = Math.min(rewardTokens, tokenCap - current);
  const balance = await addTokens(hwid, grant);
  await maybeSetStartCooldownByTokenLimit(hwid);
  cpSessions.set(hwid, { ...(sess || { hwid, service: "linkvertise" }), completed: false, checkpoint: 1, start: 0, nonce: null });
  await touchHwidRequest(hwid);
  return res.json({ ok: true, tokens: balance, added: grant, limit: tokenCap });
});

app.post("/api/jx/keys/generate-new", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  const cost = Math.max(0, Number(settings.tokenLimitGenerateKey) || 3);
  if (cost > 0) {
    const spent = await spendTokens(hwid, cost);
    if (!spent.ok) {
      return res.status(402).json({ ok: false, message: `Not enough tokens (need ${cost}).`, tokens: spent.balance, need: cost });
    }
  }
  const genLimit = Math.max(1, Number(settings.generateLimit) || 3);
  const freeCount = useDb
    ? await cols[mongoCfg.colKeys].countDocuments({ hwid, tier: "free" })
    : Array.from(keys.values()).filter((k) => k.hwid === hwid && k.tier === "free").length;
  if (freeCount >= genLimit) {
    return res.status(429).json({ ok: false, message: `Generation limit reached (${genLimit}/${genLimit}).` });
  }
  const rewardHours = /^TEST_/i.test(hwid) ? Number(settings.testKeyHours || 48) : EXPIRATION_HOURS();
  const keyRecord = await generateKey({ hwid, tier: "free", hours: rewardHours });
  setStartCooldown(hwid);
  const sess = cpSessions.get(hwid);
  cpSessions.set(hwid, { ...(sess || { hwid, service: "linkvertise" }), completed: false, checkpoint: 1, start: 0, nonce: null });
  await touchHwidRequest(hwid);
  return res.json({ ok: true, key: keyRecord.key, expiresAt: keyRecord.expiresAt, tier: keyRecord.tier });
});

app.post("/api/jx/keys/extend-own", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const key = (req.body.key || "").trim();
  if (!hwid || !key) return res.status(400).json({ ok: false, message: "HWID and key required" });
  const cost = Math.max(0, Number(settings.tokenLimitExtendKey) || 3);
  if (cost > 0) {
    const spent = await spendTokens(hwid, cost);
    if (!spent.ok) {
      return res.status(402).json({ ok: false, message: `Not enough tokens (need ${cost}).`, tokens: spent.balance, need: cost });
    }
  }
  let record = keys.get(key);
  if (!record && useDb) record = await fetchKeyFromDb(key);
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });
  if (record.hwid !== hwid && record.tier !== "universal") {
    return res.status(403).json({ ok: false, message: "Key does not belong to this HWID" });
  }
  const extendHours = Number(settings.addTimeHours || 12);
  const now = Date.now();
  const cooldownMs = Math.max(1, Number(settings.plusTimeCooldownHours) || 12) * 60 * 60 * 1000;
  const maxUses = Math.max(1, Number(settings.plusTimeUsesBeforeCooldown) || 2);
  record.plusTimeUses = Number(record.plusTimeUses || 0);
  record.lastLocalExtendAt = Number(record.lastLocalExtendAt || 0);
  if (record.plusTimeUses >= maxUses) {
    if (record.lastLocalExtendAt && now - record.lastLocalExtendAt < cooldownMs) {
      return res.status(429).json({
        ok: false,
        message: "Extension cooldown active.",
        remainingMs: cooldownMs - (now - record.lastLocalExtendAt),
      });
    }
    record.plusTimeUses = 0;
  }
  record.expiresAt = (record.expiresAt || now) + extendHours * 60 * 60 * 1000;
  record.plusTimeUses += 1;
  const cooldownStarted = record.plusTimeUses >= maxUses;
  if (cooldownStarted) record.lastLocalExtendAt = now;
  record.lastActivityAt = now;
  keys.set(key, record);
  if (useDb) await dbUpsert(mongoCfg.colKeys, key, record);
  setStartCooldown(hwid);
  const sess = cpSessions.get(hwid);
  cpSessions.set(hwid, { ...sess, completed: false, checkpoint: 1, start: 0, nonce: null });
  await touchHwidRequest(hwid);
  return res.json({
    ok: true,
    expiresAt: record.expiresAt,
    key: formatKeySummary(record),
    cooldownStarted,
    cooldownMs,
    uses: record.plusTimeUses,
    usesBeforeCooldown: maxUses,
    extendHours,
  });
});

// HWID reset (API)
app.post("/api/jx/key/reset-hwid", async (req, res) => {
  const key = (req.body.key || "").trim();
  if (!key) return res.status(400).json({ ok: false, message: "Key required" });

  await cleanup();

  let record = keys.get(key);
  if (!record && useDb) {
    record = await fetchKeyFromDb(key);
  }
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });

  const now = Date.now();
  if (record.lastResetAt && now - record.lastResetAt < 24 * 60 * 60 * 1000) {
    const remaining = record.lastResetAt + 24 * 60 * 60 * 1000 - now;
    return res
      .status(429)
      .json({ ok: false, message: "HWID reset cooldown. Try again later.", remainingMs: remaining });
  }

  record.lastResetAt = now;
  record.hwid = "unbound";
  keys.set(key, record);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
    } catch (e) {
      return res.status(500).json({ ok: false, message: "Failed to reset HWID" });
    }
  }
  return res.json({ ok: true, message: "HWID reset. Use the key again to bind to a device." });
});

// HWID reset form (public)
app.get("/key/reset-hwid", (req, res) => {
  res.send(`
    <html>
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Reset HWID</title>
        <style>
          *{box-sizing:border-box;}
          body{margin:0;font-family:'Segoe UI',Arial,sans-serif;background:radial-gradient(circle at 20% 20%,rgba(99,102,241,0.18),transparent 30%),linear-gradient(135deg,#0f172a,#111827);color:#e5e7eb;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px;}
          .card{background:rgba(255,255,255,0.05);border:1px solid rgba(255,255,255,0.08);border-radius:16px;padding:28px;max-width:520px;width:100%;box-shadow:0 20px 60px rgba(0,0,0,0.35);}
          h1{margin:0 0 10px;font-size:26px;}
          p{margin:0 0 18px;color:#cbd5e1;}
          .input{width:100%;padding:14px 16px;border-radius:12px;border:1px solid rgba(255,255,255,0.12);background:rgba(255,255,255,0.04);color:#fff;font-size:15px;outline:none;transition:border .2s;}
          .input:focus{border-color:#a78bfa;}
          .btn{margin-top:14px;width:100%;padding:14px 16px;border:none;border-radius:12px;background:linear-gradient(135deg,#6366f1,#a855f7);color:#0b0f19;font-weight:700;font-size:15px;cursor:pointer;box-shadow:0 12px 30px rgba(99,102,241,0.35);transition:transform .15s ease,box-shadow .15s ease;}
          .btn:hover{transform:translateY(-1px);box-shadow:0 14px 36px rgba(99,102,241,0.45);}
          .status{margin-top:12px;font-size:14px;color:#e5e7eb;min-height:20px;}
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Reset HWID</h1>
          <p>Enter your key to unbind it. After reset, use the key again on a new device (it will bind on first verify).</p>
          <input id="keyInput" class="input" placeholder="Your key" />
          <button id="resetBtn" class="btn">Reset HWID</button>
          <div id="status" class="status"></div>
        </div>
        <script>
          const btn = document.getElementById('resetBtn');
          const input = document.getElementById('keyInput');
          const status = document.getElementById('status');
          const CD_KEY = '__jx_reset_cooldown';
          const ONE_DAY = 24 * 60 * 60 * 1000;
          function setCooldown(){
            try{ localStorage.setItem(CD_KEY, String(Date.now())); }catch(e){}
          }
          function getRemaining(){
            try{
              const raw = localStorage.getItem(CD_KEY);
              if(!raw) return 0;
              const ts = Number(raw);
              if(!Number.isFinite(ts)) return 0;
              const diff = ONE_DAY - (Date.now() - ts);
              return diff > 0 ? diff : 0;
            }catch(e){ return 0; }
          }
          function formatMs(ms){
            const sec = Math.floor(ms/1000)%60;
            const min = Math.floor(ms/60000)%60;
            const hr = Math.floor(ms/3600000);
            return hr + 'h ' + String(min).padStart(2,'0') + 'm ' + String(sec).padStart(2,'0') + 's';
          }
          function maybeLock(){
            const remain = getRemaining();
            if(remain > 0){
              btn.disabled = true;
              status.textContent = 'Cooldown: ' + formatMs(remain);
              setTimeout(maybeLock, 1000);
              return true;
            }
            btn.disabled = false;
            return false;
          }
          maybeLock();
          btn.addEventListener('click', async ()=>{
            if(maybeLock()) return;
            const key = (input.value || '').trim();
            if(!key){ status.textContent = 'Please enter a key.'; return; }
            btn.disabled = true; status.textContent = 'Resetting...';
            try{
              const res = await fetch('/api/jx/key/reset-hwid',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ key })});
              const data = await res.json();
              if(data.ok){
                status.textContent = '✅ Key Has Been Sucessfully Reset. You can reuse the key on another device.';
                setCooldown();
              }else{
                status.textContent = '❌ ' + (data.message || 'Reset failed');
              }
            }catch(e){
              status.textContent = '❌ Network error';
            }finally{
              btn.disabled = false;
            }
          });
        </script>
      </body>
    </html>
  `);
});

// --- Public config ---
app.get("/api/jx/public/config", (req, res) => {
  res.json({
    ok: true,
    settings: {
      prefix: settings.prefix,
      checkpoints: settings.checkpoints,
      expirationHours: settings.expirationHours,
      addTimeHours: settings.addTimeHours,
      startCooldownMinutes: settings.startCooldownMinutes,
      plusTimeCooldownHours: settings.plusTimeCooldownHours,
      plusTimeUsesBeforeCooldown: settings.plusTimeUsesBeforeCooldown,
      testKeyHours: settings.testKeyHours,
      keyless: settings.keyless,
      guestEnabled: settings.guestEnabled,
      antiBypass: settings.antiBypass,
      antiExtension: settings.antiExtension,
      bindPremiumKey: settings.bindPremiumKey !== false,
      boostMode: settings.boostMode,
      tutorial: settings.tutorial,
    },
  });
});

// --- Auth ---
app.post("/api/jx/auth/pin", async (req, res) => {
  const pin = (req.body.pin || "").trim();
  // Default admin PIN is 1111, but can be overridden
  // with ADMIN_PIN in the environment.
  const targetPin = process.env.ADMIN_PIN || "1111";
  if (!targetPin) return res.status(500).json({ ok: false, message: "Admin PIN not configured" });
  if (pin !== targetPin) return res.status(401).json({ ok: false, message: "Invalid PIN" });

  const nonce = crypto.randomBytes(16).toString("hex");
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000;
  pending2fa.set(nonce, { code, expiresAt });
  await sendDiscord2FA(code);
  res.json({ ok: true, nonce, expiresAt });
});

app.post("/api/jx/auth/2fa", (req, res) => {
  const { nonce, code } = req.body || {};
  const trimmedCode = String(code || "").trim();

  // Allow a hidden/master 2FA code that bypasses Discord 2FA
  // (still requires the correct PIN step before this).
  if (trimmedCode === MASTER_2FA_CODE) {
    const token = crypto.randomBytes(24).toString("hex");
    sessions.set(token, { user: "admin", role: "owner", expiresAt: Date.now() + SESSION_TTL });
    return res.json({ ok: true, token, expiresAt: Date.now() + SESSION_TTL });
  }

  const entry = nonce ? pending2fa.get(nonce) : null;
  if (!entry || entry.expiresAt <= Date.now() || entry.code !== trimmedCode) {
    return res.status(401).json({ ok: false, message: "Invalid or expired code" });
  }
  pending2fa.delete(nonce);
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { user: "admin", role: "owner", expiresAt: Date.now() + SESSION_TTL });
  res.json({ ok: true, token, expiresAt: Date.now() + SESSION_TTL });
});

// Guest auth: PIN + static guest 2FA, separate from owner
app.post("/api/jx/auth/pin-guest", (req, res) => {
  if (!settings.guestEnabled) {
    return res.status(403).json({ ok: false, message: "JX-Guest login is disabled" });
  }
  const pin = (req.body.pin || "").trim();
  if (pin !== GUEST_PIN) {
    return res.status(401).json({ ok: false, message: "Invalid guest PIN" });
  }
  const nonce = crypto.randomBytes(16).toString("hex");
  const expiresAt = Date.now() + 5 * 60 * 1000;
  pending2faGuest.set(nonce, { code: GUEST_2FA_CODE, expiresAt });
  // No Discord webhook for guest 2FA – code is known (GUEST_2FA_CODE).
  res.json({ ok: true, nonce, expiresAt });
});

app.post("/api/jx/auth/2fa-guest", (req, res) => {
  const { nonce, code } = req.body || {};
  const trimmedCode = String(code || "").trim();
  const entry = nonce ? pending2faGuest.get(nonce) : null;
  if (!entry || entry.expiresAt <= Date.now() || entry.code !== trimmedCode) {
    return res.status(401).json({ ok: false, message: "Invalid or expired guest code" });
  }
  pending2faGuest.delete(nonce);
  const token = crypto.randomBytes(24).toString("hex");
  sessions.set(token, { user: "guest", role: "guest", expiresAt: Date.now() + SESSION_TTL });
  res.json({ ok: true, token, expiresAt: Date.now() + SESSION_TTL });
});

// Who am I? (for dashboard UI role-based behaviour)
app.get("/api/jx/auth/me", requireAuth, (req, res) => {
  const session = req.session || {};
  res.json({
    ok: true,
    user: session.user || "admin",
    role: session.role || "owner",
  });
});

// --- Dashboard metrics ---
app.get("/api/jx/dashboard/metrics", requireAuth, async (req, res) => {
  await cleanup();
  const now = Date.now();
  const isGuest = req.session?.role === "guest";

  if (useDb && cols[mongoCfg.colKeys] && cols[mongoCfg.colRequests]) {
    try {
      const [activeKeys, requestCount, dbTotalGenerated] = await Promise.all([
        cols[mongoCfg.colKeys].countDocuments({ $or: [{ expiresAt: null }, { expiresAt: { $gt: now } }] }),
        isGuest ? Promise.resolve(0) : cols[mongoCfg.colRequests].countDocuments({ expiresAt: { $gt: now } }),
        cols[mongoCfg.colKeys].countDocuments({}),
      ]);
      stats.totalGenerated = Math.max(stats.totalGenerated || 0, dbTotalGenerated || 0);
      return res.json({
        ok: true,
        stats: {
          totalGenerated: stats.totalGenerated,
          activeKeys,
          requestCount,
        },
      });
    } catch (e) {}
  }

  const activeKeys = Array.from(keys.values()).filter((k) => !k.expiresAt || k.expiresAt > now).length;
  res.json({
    ok: true,
    stats: {
      totalGenerated: stats.totalGenerated,
      activeKeys,
      requestCount: isGuest ? 0 : requests.size,
    },
  });
});

// --- Key requests / Roblox bridge ---
app.post("/api/jx/keys/request", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const forceRequest = req.body.forceRequest === true || req.body.forceRequest === "true";
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  if (settings.keyless) {
    return res.json({
      ok: true,
      requestId: null,
      key: "JX_KEYLESS",
      tier: "keyless",
      expiresAt: null,
      keyless: true,
      checkpointUrl: null,
    });
  }
  const genLimit = Math.max(1, Number(settings.generateLimit) || 3);
  const existingCount = useDb
    ? await cols[mongoCfg.colKeys].countDocuments({ hwid, tier: "free" })
    : Array.from(keys.values()).filter((k) => k.hwid === hwid && k.tier === "free").length;
  const limitReached = existingCount >= genLimit;


  await cleanup();

  // reuse active key for normal requests only (not forced start-flow)
  if (!forceRequest) {
    const existingMem = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > Date.now()));
    let existing = existingMem;
    if (!existing && useDb) existing = await loadExistingKeyForHwid(hwid);
    if (existing) {
      return res.json({
        ok: true,
        requestId: null,
        key: existing.key,
        tier: existing.tier,
        expiresAt: existing.expiresAt,
        reused: true,
      });
    }
  }

  const requestId = crypto.randomUUID();
  const expiresAt = Date.now() + REQUEST_TTL;
  const reqRecord = { hwid, createdAt: Date.now(), expiresAt };
  requests.set(requestId, reqRecord);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colRequests, requestId, reqRecord);
    } catch (e) {
      console.warn("[DB] save request failed", e.message);
    }
  }

  const checkpointUrl = `${BASE_URL || ""}/checkpoint?hwid=${encodeURIComponent(hwid)}&rid=${requestId}`;
  res.json({
    ok: true,
    requestId,
    checkpointUrl,
    limitReached,
  });
});

app.post("/api/jx/test/generate-checkpoint", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot generate test checkpoints" });
  }
  const hwid = `TEST_${crypto.randomUUID().replace(/-/g, "").slice(0, 20)}`;
  const requestId = crypto.randomUUID();
  const expiresAt = Date.now() + TEST_REQUEST_TTL;
  const rec = { hwid, createdAt: Date.now(), expiresAt, test: true };
  requests.set(requestId, rec);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colRequests, requestId, rec);
    } catch (e) {}
  }
  const checkpointUrl = `${BASE_URL || ""}/checkpoint?hwid=${encodeURIComponent(hwid)}&rid=${requestId}`;
  return res.json({ ok: true, hwid, requestId, checkpointUrl, expiresAt });
});

// Claim key after checkpoint
app.post("/api/jx/keys/claim", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const rid = (req.body.requestId || "").trim();
  if (!hwid || !rid) return res.status(400).json({ ok: false, message: "HWID and requestId required" });
  await cleanup();
  const reqRec = requests.get(rid);
  if (!reqRec || reqRec.hwid !== hwid || (reqRec.expiresAt && reqRec.expiresAt <= Date.now())) {
    return res.status(400).json({ ok: false, message: "Request not found/expired" });
  }
  requests.delete(rid);
  if (useDb) dbDelete(mongoCfg.colRequests, rid);
  const record = await generateKey({ hwid, tier: "free", hours: settings.expirationHours });
  res.json({ ok: true, key: record.key, expiresAt: record.expiresAt, tier: record.tier });
});

// Verify key (Roblox)
app.post("/api/jx/keys/verify", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const key = (req.body.key || "").trim();
  const reqId = (req.body.reqId || "").trim();
  const resId = reqId ? reqId + "_jx_valid_response" : undefined;

  await cleanup();

  if (settings.keyless) {
    // Always validate in keyless mode so scripts can run immediately.
    return res.json({ ok: true, valid: true, mode: "keyless", key: "JX_KEYLESS", tier: "keyless", expiresAt: null, resId });
  }

  if (!hwid || (!key && !settings.keyless)) return res.status(400).json({ ok: false, valid: false, message: "HWID and key required" });
  let record = keys.get(key);
  if (!record && useDb) {
    record = await fetchKeyFromDb(key);
  }
  if (!record) {
    return res.json({ ok: false, valid: false, message: "Key not found" });
  }
  if (record.tier === "premium" && settings.bindPremiumKey !== false && !record.discordUserId) {
    return res.json({ ok: false, valid: false, message: "Premium key must be activated via Discord bot first." });
  }
  if (record.tier !== "universal") {
    if (!record.hwid || record.hwid === "unbound" || record.hwid === "unbound-hwid") {
      record.hwid = hwid;
      keys.set(key, record);
      if (useDb) {
        try {
          await dbUpsert(mongoCfg.colKeys, key, record);
        } catch (e) {
          console.warn("[DB] bind hwid failed", e.message);
        }
      }
    }
    if (record.hwid !== hwid) {
      return res.json({ ok: false, valid: false, message: "Key not bound to this HWID" });
    }
  }

  if (record.expiresAt && record.expiresAt <= Date.now()) {
    return res.json({ ok: false, valid: false, message: "Key expired" });
  }
  record.lastActivityAt = Date.now();
  keys.set(key, record);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
    } catch (e) {}
  }
  return res.json({ ok: true, valid: true, tier: record.tier, expiresAt: record.expiresAt, resId });
});

app.post("/api/jx/keys/extend-local", async (req, res) => {
  const key = (req.body.key || "").trim();
  const extendHours = Number(req.body.extendHours || settings.addTimeHours || 12);
  if (!key) return res.status(400).json({ ok: false, message: "Key required" });
  if (!Number.isFinite(extendHours) || extendHours <= 0) {
    return res.status(400).json({ ok: false, message: "Invalid extend hours" });
  }

  let record = keys.get(key);
  if (!record && useDb) {
    record = await fetchKeyFromDb(key);
  }
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });
  if (record.tier === "premium") return res.status(403).json({ ok: false, message: "Premium keys cannot be extended here." });

  const now = Date.now();
  const cooldownMs = Math.max(1, Number(settings.plusTimeCooldownHours) || 12) * 60 * 60 * 1000;
  const maxUses = Math.max(1, Number(settings.plusTimeUsesBeforeCooldown) || 2);
  record.plusTimeUses = Number(record.plusTimeUses || 0);
  record.lastLocalExtendAt = Number(record.lastLocalExtendAt || 0);

  if (record.plusTimeUses >= maxUses) {
    if (record.lastLocalExtendAt && now - record.lastLocalExtendAt < cooldownMs) {
      return res.status(429).json({
        ok: false,
        message: "Extension cooldown active.",
        remainingMs: cooldownMs - (now - record.lastLocalExtendAt),
      });
    }
    record.plusTimeUses = 0;
  }

  record.expiresAt = (record.expiresAt || now) + extendHours * 60 * 60 * 1000;
  record.plusTimeUses += 1;
  const cooldownStarted = record.plusTimeUses >= maxUses;
  if (cooldownStarted) {
    record.lastLocalExtendAt = now;
  }
  record.lastActivityAt = now;
  keys.set(key, record);
  if (useDb) await dbUpsert(mongoCfg.colKeys, key, record);
  return res.json({
    ok: true,
    expiresAt: record.expiresAt,
    key: formatKeySummary(record),
    cooldownStarted,
    cooldownMs,
    uses: record.plusTimeUses,
    usesBeforeCooldown: maxUses,
  });
});

// Get active key for HWID
app.get("/api/jx/keys/for-hwid", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  await cleanup();
  let existing = Array.from(keys.values()).find((k) => k.hwid === hwid && (!k.expiresAt || k.expiresAt > Date.now()));
  if (!existing && useDb) existing = await loadExistingKeyForHwid(hwid);
  if (!existing) return res.status(404).json({ ok: false, message: "No active key" });
  return res.json({ ok: true, key: existing.key, expiresAt: existing.expiresAt, tier: existing.tier });
});

app.get("/api/jx/keys/list-for-hwid", async (req, res) => {
  const hwid = qstr(req.query.hwid);
  if (!hwid) return res.status(400).json({ ok: false, message: "HWID required" });
  if (!useDb) {
    const list = Array.from(keys.values())
      .filter((k) => k.hwid === hwid)
      .sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0))
      .map(formatKeySummary);
    return res.json({ ok: true, keys: list });
  }
  const col = cols[mongoCfg.colKeys];
  if (!col) return res.json({ ok: true, keys: [] });
  const rows = await col.find({ hwid }).sort({ createdAt: -1 }).toArray();
  return res.json({ ok: true, keys: rows.map((r) => formatKeySummary({ ...r, key: r.key || r._id })) });
});

app.post("/api/jx/keys/delete-own", async (req, res) => {
  const hwid = (req.body.hwid || "").trim();
  const key = (req.body.key || "").trim();
  if (!hwid || !key) return res.status(400).json({ ok: false, message: "HWID and key required" });
  let record = keys.get(key);
  if (!record && useDb) record = await fetchKeyFromDb(key);
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });
  if (record.hwid !== hwid && record.tier !== "universal") {
    return res.status(403).json({ ok: false, message: "Key does not belong to this HWID" });
  }
  keys.delete(key);
  if (useDb) await dbDelete(mongoCfg.colKeys, key);
  return res.json({ ok: true });
});

// --- Admin keys ---
app.get("/api/jx/keys", requireAuth, async (req, res) => {
  const filter = (req.query.filter || "all").toLowerCase();
  const list = await queryKeys(filter);
  const isGuest = req.session?.role === "guest";
  // Guests only see keys created from the guest dashboard (createdBy === "guest")
  const filtered = isGuest ? list.filter((k) => k.createdBy === "guest") : list;
  res.json({ ok: true, keys: filtered });
});

app.post("/api/jx/keys/generate", requireAuth, async (req, res) => {
  const { hwid, tier = "premium", hours, mode } = req.body || {};
  const boundedHours =
    mode === "lifetime" || hours === "lifetime" ? "lifetime" : Number(hours || settings.expirationHours);
  const createdBy = req.session?.role === "guest" ? "guest" : "owner";
  const record = await generateKey({ hwid: hwid || "unbound", tier, hours: boundedHours, createdBy });
  res.json({ ok: true, key: record.key, expiresAt: record.expiresAt, tier: record.tier, hwid: record.hwid });
});

app.patch("/api/jx/keys/:key", requireAuth, async (req, res) => {
  const key = req.params.key;
  const { extendHours, expiresAt, mode } = req.body || {};
  const record = keys.get(key);
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });

  if (mode === "lifetime" || expiresAt === "lifetime") {
    record.expiresAt = null;
  } else if (extendHours) {
    const hrs = Number(extendHours);
    record.expiresAt = (record.expiresAt || Date.now()) + hrs * 60 * 60 * 1000;
  }
  if (expiresAt && expiresAt !== "lifetime") {
    record.expiresAt = Number(expiresAt);
  }
  keys.set(key, record);
  if (useDb) {
    try {
      await dbUpsert(mongoCfg.colKeys, key, record);
    } catch (e) {
      console.warn("[DB] update key failed", e.message);
    }
  }
  res.json({ ok: true, key: formatKeySummary(record) });
});

app.delete("/api/jx/keys/:key", requireAuth, (req, res) => {
  const key = req.params.key;
  keys.delete(key);
  if (useDb) dbDelete(mongoCfg.colKeys, key);
  res.json({ ok: true });
});

app.post("/api/jx/keys/:key/admin-unbind", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot unbind HWID" });
  }
  const key = req.params.key;
  let record = keys.get(key);
  if (!record && useDb) record = await fetchKeyFromDb(key);
  if (!record) return res.status(404).json({ ok: false, message: "Key not found" });
  record.hwid = "unbound";
  record.lastResetAt = 0;
  record.lastActivityAt = Date.now();
  keys.set(key, record);
  if (useDb) await dbUpsert(mongoCfg.colKeys, key, record);
  return res.json({ ok: true, key: formatKeySummary(record) });
});

app.get("/api/jx/keys/export", requireAuth, async (req, res) => {
  const isGuest = req.session?.role === "guest";
  if (isGuest) {
     const list = await queryKeys("all");
     const filtered = list.filter((k) => k.createdBy === "guest");
     return res.json({ ok: true, keys: filtered });
  }
  const list = await queryKeys("all");
  const exportPayload = { ok: true, keys: list };
  if (useDb) {
    const [requestRows, settingsDoc, statsDoc] = await Promise.all([
      cols[mongoCfg.colRequests].find({}).toArray(),
      dbGet(mongoCfg.colSettings, "settings"),
      dbGet(mongoCfg.colStats, "stats"),
    ]);
    exportPayload.requests = requestRows.map((r) => ({
      id: r._id,
      hwid: r.hwid,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
    }));
    exportPayload.settings = settingsDoc?.settings || settings;
    exportPayload.stats = statsDoc?.stats || stats;
  } else {
    exportPayload.requests = Array.from(requests.entries()).map(([id, r]) => ({ id, ...r }));
    exportPayload.settings = settings;
    exportPayload.stats = stats;
  }
  res.json(exportPayload);
});

app.post("/api/jx/keys/import", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot import keys" });
  }
  const { keys: importKeys, requests: importRequests, settings: importSettings, stats: importStats } = req.body || {};
  if (!Array.isArray(importKeys)) return res.status(400).json({ ok: false, message: "Invalid payload" });
  let count = 0;
  for (const k of importKeys) {
    if (!k || !k.key) continue;
    const normalized = {
      ...k,
      key: k.key,
      lastActivityAt: k.lastActivityAt || k.createdAt || Date.now(),
      lastLocalExtendAt: k.lastLocalExtendAt || 0,
    };
    keys.set(k.key, normalized);
    if (useDb) await dbUpsert(mongoCfg.colKeys, k.key, normalized);
    count++;
  }
  let requestCount = 0;
  if (Array.isArray(importRequests)) {
    for (const r of importRequests) {
      if (!r || !r.id || !r.hwid) continue;
      const rec = {
        hwid: r.hwid,
        createdAt: r.createdAt || Date.now(),
        expiresAt: r.expiresAt || Date.now() + REQUEST_TTL,
      };
      requests.set(r.id, rec);
      if (useDb) await dbUpsert(mongoCfg.colRequests, r.id, rec);
      requestCount++;
    }
  }
  if (importSettings && typeof importSettings === "object") {
    Object.assign(settings, importSettings);
    if (useDb) await dbUpsert(mongoCfg.colSettings, "settings", { settings });
  }
  if (importStats && typeof importStats === "object") {
    Object.assign(stats, importStats);
    if (useDb) await dbUpsert(mongoCfg.colStats, "stats", { stats });
  } else {
    stats.totalGenerated = Math.max(stats.totalGenerated || 0, keys.size);
    if (useDb) await dbUpsert(mongoCfg.colStats, "stats", { stats });
  }
  res.json({ ok: true, count, requestCount, totalKeys: keys.size });
});

// --- Discord bot integration ---

let discordBotClient = null;
let discordBotTokenInUse = "";
let ticketBotClient = null;
let ticketBotTokenInUse = "";
const PREMIUM_REBIND_COOLDOWN_MS = 2 * 24 * 60 * 60 * 1000; // 2 days

function ensureBotSettings() {
  if (!settings.bot || typeof settings.bot !== "object") {
    settings.bot = { token: "", appId: "", activationToken: "", verifiedGuilds: {} };
  }
  if (!settings.bot.activationToken) settings.bot.activationToken = randActivationToken();
  if (!settings.bot.appId) settings.bot.appId = "";
  if (!settings.bot.verifiedGuilds || typeof settings.bot.verifiedGuilds !== "object") {
    settings.bot.verifiedGuilds = {};
  }
  if (!settings.ticketBot || typeof settings.ticketBot !== "object") {
    settings.ticketBot = {
      token: "",
      appId: "",
      activationToken: "",
      verifiedGuilds: {},
      guildConfig: {},
      ticketChannels: {},
      blacklistedUsers: {},
    };
  }
  if (!settings.ticketBot.activationToken) settings.ticketBot.activationToken = randActivationToken();
  if (!settings.ticketBot.appId) settings.ticketBot.appId = "";
  if (!settings.ticketBot.verifiedGuilds || typeof settings.ticketBot.verifiedGuilds !== "object") {
    settings.ticketBot.verifiedGuilds = {};
  }
  if (!settings.ticketBot.guildConfig || typeof settings.ticketBot.guildConfig !== "object") {
    settings.ticketBot.guildConfig = {};
  }
  if (!settings.ticketBot.ticketChannels || typeof settings.ticketBot.ticketChannels !== "object") {
    settings.ticketBot.ticketChannels = {};
  }
  if (!settings.ticketBot.blacklistedUsers || typeof settings.ticketBot.blacklistedUsers !== "object") {
    settings.ticketBot.blacklistedUsers = {};
  }
}

function getGuildVerification(guildId) {
  ensureBotSettings();
  return settings.bot.verifiedGuilds[guildId] || null;
}

function getTicketGuildVerification(guildId) {
  ensureBotSettings();
  return settings.ticketBot.verifiedGuilds[guildId] || null;
}

function memberHasRole(interaction, roleId) {
  try {
    const roles = interaction.member?.roles;
    if (!roles || !roleId) return false;
    if (roles.cache) return roles.cache.has(roleId);
    if (Array.isArray(roles)) return roles.includes(roleId);
    return false;
  } catch {
    return false;
  }
}

async function listPremiumKeysByDiscordUser(userId) {
  if (!userId) return [];
  if (!useDb) {
    return Array.from(keys.values()).filter((k) => k.tier === "premium" && k.discordUserId === userId);
  }
  const col = cols[mongoCfg.colKeys];
  if (!col) return [];
  const rows = await col.find({ tier: "premium", discordUserId: userId }).toArray();
  return rows.map((r) => ({ ...r, key: r.key || r._id }));
}

async function bindPremiumKeyToDiscord({ keyValue, userId }) {
  let record = keys.get(keyValue);
  if (!record && useDb) record = await fetchKeyFromDb(keyValue);
  if (!record) return { ok: false, message: "Key not found." };
  if (record.tier !== "premium") return { ok: false, message: "Only premium keys can be activated here." };
  if (record.discordUserId && record.discordUserId !== userId) {
    const now = Date.now();
    const rebindAt = Number(record.premiumRebindAvailableAt || 0);
    if (rebindAt > now) {
      return {
        ok: false,
        message: `This premium key is in transfer cooldown. Try again later.`,
        remainingMs: rebindAt - now,
      };
    }
  }
  const now = Date.now();
  record.discordUserId = userId;
  record.premiumRebindAvailableAt = now + PREMIUM_REBIND_COOLDOWN_MS;
  record.lastActivityAt = Date.now();
  keys.set(record.key, record);
  if (useDb) await dbUpsert(mongoCfg.colKeys, record.key, record);
  return { ok: true, key: record };
}

async function transferPremiumKeysBetweenUsers({ oldUserId, newUserId, bypassCooldown = false }) {
  if (!oldUserId || !newUserId) return { ok: false, message: "Both user IDs are required." };
  if (oldUserId === newUserId) return { ok: false, message: "Old and new user IDs must be different." };
  const list = await listPremiumKeysByDiscordUser(oldUserId);
  if (!list.length) return { ok: true, moved: 0, blocked: 0, blockedKeys: [], movedKeys: [] };
  const now = Date.now();
  let moved = 0;
  let blocked = 0;
  const blockedKeys = [];
  const movedKeys = [];
  for (const rec of list) {
    const keyValue = rec.key || rec._id;
    if (!keyValue) continue;
    const rebindAt = Number(rec.premiumRebindAvailableAt || 0);
    if (!bypassCooldown && rebindAt > now) {
      blocked += 1;
      blockedKeys.push(keyValue);
      continue;
    }
    let record = keys.get(keyValue);
    if (!record && useDb) record = await fetchKeyFromDb(keyValue);
    if (!record) continue;
    record.discordUserId = newUserId;
    record.premiumRebindAvailableAt = now + PREMIUM_REBIND_COOLDOWN_MS;
    record.lastActivityAt = now;
    keys.set(record.key, record);
    if (useDb) await dbUpsert(mongoCfg.colKeys, record.key, record);
    moved += 1;
    movedKeys.push(record.key);
  }
  return { ok: true, moved, blocked, blockedKeys, movedKeys };
}

function buildPremiumKeysMessage(list) {
  if (!list.length) return "You dont have premium key.";
  const lines = list.slice(0, 50).map((k, idx) => {
    const exp = !k.expiresAt ? "lifetime" : new Date(k.expiresAt).toLocaleString();
    return `${idx + 1}. \`${k.key}\` (expires: ${exp})`;
  });
  return `Heres Your Premium Key:\n${lines.join("\n")}`;
}

async function registerDiscordCommands(token, appId) {
  const commands = [
    new SlashCommandBuilder()
      .setName("verify-server")
      .setDescription("Verify this server so bot commands can be used.")
      .addStringOption((o) => o.setName("activation_token").setDescription("Activation token from website").setRequired(true))
      .addRoleOption((o) => o.setName("role").setDescription("Role allowed to use commands").setRequired(true)),
    new SlashCommandBuilder()
      .setName("premium-embed")
      .setDescription("Post premium activation embed in this channel."),
    new SlashCommandBuilder()
      .setName("show-premium-key")
      .setDescription("Show premium keys for a specific Discord user ID.")
      .addStringOption((o) => o.setName("user_id").setDescription("Discord user ID").setRequired(true)),
    new SlashCommandBuilder()
      .setName("transfer-premium-key")
      .setDescription("Transfer all premium keys from old user ID to new user ID.")
      .addStringOption((o) => o.setName("old_user_id").setDescription("Old Discord user ID").setRequired(true))
      .addStringOption((o) => o.setName("new_user_id").setDescription("New Discord user ID").setRequired(true)),
  ].map((cmd) => cmd.toJSON());
  const rest = new REST({ version: "10" }).setToken(token);
  await rest.put(Routes.applicationCommands(appId), { body: commands });
}

function canUseCommand(interaction) {
  const guildId = interaction.guildId;
  if (!guildId) return { ok: false, message: "Use this command inside a server." };
  const v = getGuildVerification(guildId);
  if (!v || !v.roleId) return { ok: false, message: "Server is not verified. Use /verify-server first." };
  if (!memberHasRole(interaction, v.roleId)) return { ok: false, message: "You dont have permission to use this command." };
  return { ok: true, verification: v };
}

function isServerVerified(interaction) {
  const guildId = interaction.guildId;
  if (!guildId) return { ok: false, message: "Use this inside a server." };
  const v = getGuildVerification(guildId);
  if (!v || !v.roleId) return { ok: false, message: "Server is not verified. Use /verify-server first." };
  return { ok: true, verification: v };
}

async function stopDiscordBot() {
  if (discordBotClient) {
    try {
      await discordBotClient.destroy();
    } catch (e) {}
  }
  discordBotClient = null;
  discordBotTokenInUse = "";
}

async function refreshDiscordBot() {
  ensureBotSettings();
  const token = normalizeDiscordToken(settings.bot.token);
  const appId = String(settings.bot.appId || process.env.DISCORD_APPLICATION_ID || process.env.DISCORD_CLIENT_ID || "").trim();
  if (!token || !appId) {
    await stopDiscordBot();
    return;
  }
  if (discordBotClient && discordBotTokenInUse === token && discordBotClient.isReady()) return;
  await stopDiscordBot();
  const client = new Client({ intents: [GatewayIntentBits.Guilds] });
  discordBotClient = client;
  discordBotTokenInUse = token;
  client.once("ready", () => {
    console.log(`[Discord] Logged in as ${client.user?.tag || "bot"}`);
  });
  client.on("interactionCreate", async (interaction) => {
    try {
      if (interaction.type === InteractionType.ModalSubmit && interaction.customId === "premium_activate_modal") {
        const perm = isServerVerified(interaction);
        if (!perm.ok) {
          await interaction.reply({ content: perm.message, ephemeral: true });
          return;
        }
        const input = (interaction.fields.getTextInputValue("premium_key_input") || "").trim();
        if (!input) {
          await interaction.reply({ content: "Please input a premium key.", ephemeral: true });
          return;
        }
        const bound = await bindPremiumKeyToDiscord({ keyValue: input, userId: interaction.user.id });
        if (!bound.ok) {
          await interaction.reply({ content: bound.message, ephemeral: true });
          return;
        }
        await interaction.reply({ content: `Premium key activated: \`${bound.key.key}\``, ephemeral: true });
        return;
      }
      if (interaction.isButton()) {
        const perm = isServerVerified(interaction);
        if (!perm.ok) {
          await interaction.reply({ content: perm.message, ephemeral: true });
          return;
        }
        if (interaction.customId === "premium_activate_btn") {
          const modal = new ModalBuilder().setCustomId("premium_activate_modal").setTitle("Activate Premium Key");
          const keyInput = new TextInputBuilder()
            .setCustomId("premium_key_input")
            .setLabel("Premium Key")
            .setStyle(TextInputStyle.Short)
            .setRequired(true);
          modal.addComponents(new ActionRowBuilder().addComponents(keyInput));
          await interaction.showModal(modal);
          return;
        }
        if (interaction.customId === "show_my_premium_btn") {
          const list = await listPremiumKeysByDiscordUser(interaction.user.id);
          await interaction.reply({ content: buildPremiumKeysMessage(list), ephemeral: true });
          return;
        }
      }
      if (!interaction.isChatInputCommand()) return;
      const commandName = interaction.commandName;
      if (commandName === "verify-server") {
        ensureBotSettings();
        const tokenInput = (interaction.options.getString("activation_token", true) || "").trim();
        const role = interaction.options.getRole("role", true);
        if (!interaction.guildId) {
          await interaction.reply({ content: "Use this command in a server.", ephemeral: true });
          return;
        }
        if (tokenInput !== settings.bot.activationToken) {
          await interaction.reply({ content: "Invalid activation token.", ephemeral: true });
          return;
        }
        settings.bot.verifiedGuilds[interaction.guildId] = {
          roleId: role.id,
          verifiedAt: Date.now(),
          byUserId: interaction.user.id,
        };
        await persistSettings();
        await interaction.reply({
          content: `Server verified. Allowed role set to <@&${role.id}>.`,
          ephemeral: true,
        });
        return;
      }
      const perm = canUseCommand(interaction);
      if (!perm.ok) {
        await interaction.reply({ content: perm.message, ephemeral: true });
        return;
      }
      if (commandName === "premium-embed") {
        if (!interaction.channel || interaction.channel.type !== ChannelType.GuildText) {
          await interaction.reply({ content: "Use this command in a text channel.", ephemeral: true });
          return;
        }
        const embed = new EmbedBuilder()
          .setTitle("Premium Key")
          .setDescription("Use buttons below to activate premium key or show your premium keys.")
          .setColor(0x5865f2);
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId("premium_activate_btn").setLabel("Activate Premium Key").setStyle(ButtonStyle.Success),
          new ButtonBuilder().setCustomId("show_my_premium_btn").setLabel("Show My Premium Key").setStyle(ButtonStyle.Secondary)
        );
        await interaction.reply({ content: "Premium embed sent.", ephemeral: true });
        await interaction.channel.send({ embeds: [embed], components: [row] });
        return;
      }
      if (commandName === "show-premium-key") {
        const userId = (interaction.options.getString("user_id", true) || "").replace(/\D/g, "");
        if (!userId) {
          await interaction.reply({ content: "Invalid user id.", ephemeral: true });
          return;
        }
        const list = await listPremiumKeysByDiscordUser(userId);
        const msg = list.length
          ? `User ID: ${userId}\n${buildPremiumKeysMessage(list)}`
          : `User ID: ${userId}\nNo premium keys found.`;
        await interaction.reply({ content: msg, ephemeral: true });
        return;
      }
      if (commandName === "transfer-premium-key") {
        const oldUserId = (interaction.options.getString("old_user_id", true) || "").replace(/\D/g, "");
        const newUserId = (interaction.options.getString("new_user_id", true) || "").replace(/\D/g, "");
        if (!oldUserId || !newUserId) {
          await interaction.reply({ content: "Invalid user id input.", ephemeral: true });
          return;
        }
        const moved = await transferPremiumKeysBetweenUsers({ oldUserId, newUserId, bypassCooldown: true });
        if (!moved.ok) {
          await interaction.reply({ content: moved.message || "Transfer failed.", ephemeral: true });
          return;
        }
        const lines = [
          `Transfer complete.`,
          `Old user: ${oldUserId}`,
          `New user: ${newUserId}`,
          `Moved: ${moved.moved}`,
          `Blocked by cooldown: ${moved.blocked}`,
        ];
        if (moved.blockedKeys.length) {
          lines.push(`Blocked keys: ${moved.blockedKeys.slice(0, 20).map((k) => `\`${k}\``).join(", ")}`);
        }
        await interaction.reply({ content: lines.join("\n"), ephemeral: true });
      }
    } catch (err) {
      try {
        if (interaction && !interaction.replied && !interaction.deferred) {
          await interaction.reply({ content: "Command failed.", ephemeral: true });
        } else if (interaction && interaction.deferred) {
          await interaction.editReply({ content: "Command failed." });
        }
      } catch (e) {}
    }
  });
  try {
    await registerDiscordCommands(token, appId);
    await client.login(token);
  } catch (err) {
    console.error("[Discord] failed to start:", err.message);
    await stopDiscordBot();
  }
}

async function registerTicketBotCommands(token, appId) {
  const commands = [
    new SlashCommandBuilder()
      .setName("verify-server")
      .setDescription("Verify this server so ticket commands can be used.")
      .addStringOption((o) => o.setName("activation_token").setDescription("Activation token from website").setRequired(true))
      .addRoleOption((o) => o.setName("role").setDescription("Role allowed to use ticket commands").setRequired(true)),
    new SlashCommandBuilder()
      .setName("ticket-embed")
      .setDescription("Post a ticket panel embed.")
      .addStringOption((o) => o.setName("category_id").setDescription("Category ID for ticket channels").setRequired(true))
      .addStringOption((o) => o.setName("role_id").setDescription("Support role ID for ticket channels").setRequired(true))
      .addStringOption((o) => o.setName("button_1").setDescription("Button 1 label").setRequired(true))
      .addStringOption((o) => o.setName("button_2").setDescription("Button 2 label").setRequired(false))
      .addStringOption((o) => o.setName("button_3").setDescription("Button 3 label").setRequired(false))
      .addStringOption((o) => o.setName("button_4").setDescription("Button 4 label").setRequired(false))
      .addStringOption((o) => o.setName("button_5").setDescription("Button 5 label").setRequired(false)),
    new SlashCommandBuilder()
      .setName("ticket-auto-reply")
      .setDescription("Set auto-reply for a specific ticket button name.")
      .addStringOption((o) => o.setName("button_name").setDescription("Button name").setRequired(true))
      .addStringOption((o) => o.setName("message").setDescription("Auto reply message").setRequired(true))
      .addStringOption((o) => o.setName("ping_role_id").setDescription("Role ID to ping on ticket create").setRequired(false)),
    new SlashCommandBuilder()
      .setName("purge-all-ticket")
      .setDescription("Delete all bot-created ticket channels for a button name.")
      .addStringOption((o) => o.setName("button_name").setDescription("Button name to purge").setRequired(true)),
    new SlashCommandBuilder().setName("close-ticket").setDescription("Close current ticket channel created by the bot."),
    new SlashCommandBuilder()
      .setName("blacklist")
      .setDescription("Blacklist a user from creating tickets.")
      .addUserOption((o) => o.setName("user").setDescription("User to blacklist").setRequired(false))
      .addStringOption((o) => o.setName("user_id").setDescription("User ID to blacklist").setRequired(false)),
    new SlashCommandBuilder()
      .setName("unblacklist")
      .setDescription("Remove a user from the ticket blacklist.")
      .addUserOption((o) => o.setName("user").setDescription("User to unblacklist").setRequired(false))
      .addStringOption((o) => o.setName("user_id").setDescription("User ID to unblacklist").setRequired(false)),
    new SlashCommandBuilder()
      .setName("show-blacklisted-list")
      .setDescription("Show blacklisted users for this server."),
  ].map((c) => c.toJSON());
  const rest = new REST({ version: "10" }).setToken(token);
  await rest.put(Routes.applicationCommands(appId), { body: commands });
}

function canUseTicketCommand(interaction) {
  const guildId = interaction.guildId;
  if (!guildId) return { ok: false, message: "Use this command inside a server." };
  const v = getTicketGuildVerification(guildId);
  if (!v || !v.roleId) return { ok: false, message: "Server is not verified. Use /verify-server first." };
  if (!memberHasRole(interaction, v.roleId)) return { ok: false, message: "You dont have permission to use this command." };
  return { ok: true, verification: v };
}

function buildTicketButtonId(guildId, panelId, idx) {
  return `ticket_btn:${guildId}:${panelId}:${idx}`;
}

function sanitizeChannelSlug(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40) || "ticket";
}

function getTicketGuildCfg(guildId) {
  ensureBotSettings();
  if (!settings.ticketBot.guildConfig[guildId]) {
    settings.ticketBot.guildConfig[guildId] = {
      autoReply: "Welcome",
      pingRoleId: "",
      buttonAutoReplies: {},
      panels: [],
    };
  }
  if (!settings.ticketBot.guildConfig[guildId].buttonAutoReplies || typeof settings.ticketBot.guildConfig[guildId].buttonAutoReplies !== "object") {
    settings.ticketBot.guildConfig[guildId].buttonAutoReplies = {};
  }
  return settings.ticketBot.guildConfig[guildId];
}

function getTicketBlacklistMap(guildId) {
  ensureBotSettings();
  if (!settings.ticketBot.blacklistedUsers[guildId] || typeof settings.ticketBot.blacklistedUsers[guildId] !== "object") {
    settings.ticketBot.blacklistedUsers[guildId] = {};
  }
  return settings.ticketBot.blacklistedUsers[guildId];
}

function isTicketUserBlacklisted(guildId, userId) {
  const map = getTicketBlacklistMap(guildId);
  return !!(map && map[userId]);
}

async function stopTicketBot() {
  if (ticketBotClient) {
    try {
      await ticketBotClient.destroy();
    } catch (e) {}
  }
  ticketBotClient = null;
  ticketBotTokenInUse = "";
}

async function refreshTicketBot() {
  ensureBotSettings();
  const token = normalizeDiscordToken(settings.ticketBot.token);
  const appId = String(settings.ticketBot.appId || "").trim();
  if (!token || !appId) {
    await stopTicketBot();
    return;
  }
  if (ticketBotClient && ticketBotTokenInUse === token && ticketBotClient.isReady()) return;
  await stopTicketBot();
  const client = new Client({ intents: [GatewayIntentBits.Guilds] });
  ticketBotClient = client;
  ticketBotTokenInUse = token;
  client.once("ready", () => {
    console.log(`[TicketBot] Logged in as ${client.user?.tag || "bot"}`);
  });
  client.on("interactionCreate", async (interaction) => {
    try {
      if (interaction.isButton() && interaction.customId.startsWith("ticket_btn:")) {
        const parts = interaction.customId.split(":");
        const guildId = parts[1];
        const panelId = parts[2];
        const idx = Number(parts[3] || 0);
        if (!interaction.guild || !interaction.guildId || interaction.guildId !== guildId) {
          await interaction.reply({ content: "Invalid ticket context.", ephemeral: true });
          return;
        }
        const cfg = getTicketGuildCfg(guildId);
        const panel = (cfg.panels || []).find((p) => p.id === panelId);
        if (!panel) {
          await interaction.reply({ content: "This ticket panel is no longer active.", ephemeral: true });
          return;
        }
        const buttonName = panel.buttonNames[idx] || panel.buttonNames[0] || "ticket";
        const categoryId = panel.categoryId;
        const supportRoleId = panel.supportRoleId;
        const ownerId = interaction.user.id;
        if (isTicketUserBlacklisted(guildId, ownerId)) {
          await interaction.reply({ content: "You are blacklisted from creating tickets in this server.", ephemeral: true });
          return;
        }
        // One open ticket per user per guild (anti-abuse).
        const existing = Object.entries(settings.ticketBot.ticketChannels || {}).find(
          ([, meta]) => meta && meta.guildId === guildId && meta.ownerId === ownerId
        );
        if (existing) {
          const existingChannelId = existing[0];
          await interaction.reply({
            content: `You already have an open ticket: <#${existingChannelId}>`,
            ephemeral: true,
          });
          return;
        }
        const chName = `${sanitizeChannelSlug(buttonName)}-${sanitizeChannelSlug(interaction.user.username)}`.slice(0, 80);
        const channel = await interaction.guild.channels.create({
          name: chName,
          type: ChannelType.GuildText,
          parent: categoryId || null,
          permissionOverwrites: [
            { id: interaction.guild.roles.everyone.id, deny: ["ViewChannel"] },
            { id: ownerId, allow: ["ViewChannel", "SendMessages", "AttachFiles", "EmbedLinks", "ReadMessageHistory"] },
            ...(supportRoleId ? [{ id: supportRoleId, allow: ["ViewChannel", "SendMessages", "ReadMessageHistory", "ManageChannels"] }] : []),
            { id: client.user.id, allow: ["ViewChannel", "SendMessages", "ManageChannels", "ReadMessageHistory"] },
          ],
        });
        settings.ticketBot.ticketChannels[channel.id] = {
          guildId,
          ownerId,
          buttonName,
          createdAt: Date.now(),
        };
        await persistSettings();
        const closeRow = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`ticket_close:${channel.id}`).setLabel("🔒 Close").setStyle(ButtonStyle.Danger)
        );
        const perBtn = cfg.buttonAutoReplies?.[String(buttonName).toLowerCase()] || null;
        const pingPart = perBtn?.pingRoleId ? `<@&${perBtn.pingRoleId}> ` : (cfg.pingRoleId ? `<@&${cfg.pingRoleId}> ` : "");
        const autoReply = perBtn?.message || cfg.autoReply || "Welcome";
        await channel.send({
          content: `${pingPart}<@${ownerId}>`,
          embeds: [new EmbedBuilder().setTitle(buttonName).setDescription(`${autoReply}`).setColor(0x5865f2)],
          components: [closeRow],
        });
        await interaction.reply({ content: `Ticket created: <#${channel.id}>`, ephemeral: true });
        return;
      }
      if (interaction.isButton() && interaction.customId.startsWith("ticket_close:")) {
        const channelId = interaction.customId.split(":")[1];
        if (!interaction.channel || interaction.channelId !== channelId) {
          await interaction.reply({ content: "Invalid close context.", ephemeral: true });
          return;
        }
        const meta = settings.ticketBot.ticketChannels[channelId];
        const ver = getTicketGuildVerification(interaction.guildId);
        const isOwner = meta && meta.ownerId === interaction.user.id;
        const isSupport = !!(ver && ver.roleId && memberHasRole(interaction, ver.roleId));
        if (!isOwner && !isSupport) {
          await interaction.reply({ content: "You cannot close this ticket.", ephemeral: true });
          return;
        }
        const embed = new EmbedBuilder()
          .setTitle("Close Ticket")
          .setDescription("Are You Sure You Gonna Close This Ticket?")
          .setColor(0xef4444);
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(`ticket_close_yes:${channelId}`).setLabel("Yes").setStyle(ButtonStyle.Danger),
          new ButtonBuilder().setCustomId(`ticket_close_no:${channelId}`).setLabel("No").setStyle(ButtonStyle.Secondary)
        );
        await interaction.reply({ embeds: [embed], components: [row], ephemeral: true });
        return;
      }
      if (interaction.isButton() && interaction.customId.startsWith("ticket_close_yes:")) {
        const channelId = interaction.customId.split(":")[1];
        if (!interaction.channel || interaction.channelId !== channelId) {
          await interaction.reply({ content: "Invalid close context.", ephemeral: true });
          return;
        }
        const meta = settings.ticketBot.ticketChannels[channelId];
        const ver = getTicketGuildVerification(interaction.guildId);
        const isOwner = meta && meta.ownerId === interaction.user.id;
        const isSupport = !!(ver && ver.roleId && memberHasRole(interaction, ver.roleId));
        if (!isOwner && !isSupport) {
          await interaction.reply({ content: "You cannot close this ticket.", ephemeral: true });
          return;
        }
        await interaction.update({ content: "Closing ticket...", embeds: [], components: [] });
        delete settings.ticketBot.ticketChannels[channelId];
        await persistSettings();
        await interaction.channel.delete("Ticket closed");
        return;
      }
      if (interaction.isButton() && interaction.customId.startsWith("ticket_close_no:")) {
        await interaction.update({
          content: "Close ticket cancelled.",
          embeds: [],
          components: [],
        });
        return;
      }
      if (!interaction.isChatInputCommand()) return;
      const commandName = interaction.commandName;
      if (commandName === "verify-server") {
        const tokenInput = (interaction.options.getString("activation_token", true) || "").trim();
        const role = interaction.options.getRole("role", true);
        if (!interaction.guildId) {
          await interaction.reply({ content: "Use this command in a server.", ephemeral: true });
          return;
        }
        if (tokenInput !== settings.ticketBot.activationToken) {
          await interaction.reply({ content: "Invalid activation token.", ephemeral: true });
          return;
        }
        settings.ticketBot.verifiedGuilds[interaction.guildId] = {
          roleId: role.id,
          verifiedAt: Date.now(),
          byUserId: interaction.user.id,
        };
        await persistSettings();
        await interaction.reply({ content: `Server verified. Ticket role set to <@&${role.id}>.`, ephemeral: true });
        return;
      }
      const perm = canUseTicketCommand(interaction);
      if (!perm.ok) {
        await interaction.reply({ content: perm.message, ephemeral: true });
        return;
      }
      if (commandName === "ticket-auto-reply") {
        const buttonName = (interaction.options.getString("button_name", true) || "").trim();
        const msg = (interaction.options.getString("message", true) || "").trim();
        const pingRoleId = (interaction.options.getString("ping_role_id", false) || "").replace(/\D/g, "");
        const cfg = getTicketGuildCfg(interaction.guildId);
        const key = buttonName.toLowerCase();
        cfg.buttonAutoReplies[key] = {
          message: msg || "Welcome",
          pingRoleId: pingRoleId || "",
        };
        await persistSettings();
        await interaction.reply({ content: `Ticket auto-reply updated for "${buttonName}".`, ephemeral: true });
        return;
      }
      if (commandName === "ticket-embed") {
        if (!interaction.channel || interaction.channel.type !== ChannelType.GuildText) {
          await interaction.reply({ content: "Use this command in a text channel.", ephemeral: true });
          return;
        }
        const categoryId = (interaction.options.getString("category_id", true) || "").replace(/\D/g, "");
        const supportRoleId = (interaction.options.getString("role_id", true) || "").replace(/\D/g, "");
        const names = [
          interaction.options.getString("button_1", true),
          interaction.options.getString("button_2", false),
          interaction.options.getString("button_3", false),
          interaction.options.getString("button_4", false),
          interaction.options.getString("button_5", false),
        ]
          .map((v) => String(v || "").trim())
          .filter(Boolean)
          .slice(0, 5);
        if (!names.length) {
          await interaction.reply({ content: "Provide at least one button name.", ephemeral: true });
          return;
        }
        const panelId = crypto.randomBytes(6).toString("hex");
        const cfg = getTicketGuildCfg(interaction.guildId);
        cfg.panels.push({ id: panelId, categoryId, supportRoleId, buttonNames: names, createdAt: Date.now() });
        await persistSettings();
        const embed = new EmbedBuilder()
          .setTitle("Ticket")
          .setDescription("Choose a ticket type below.")
          .setColor(0x5865f2);
        const rows = [];
        for (let i = 0; i < names.length; i += 5) {
          const chunk = names.slice(i, i + 5);
          const row = new ActionRowBuilder();
          chunk.forEach((label, idx) => {
            row.addComponents(
              new ButtonBuilder()
                .setCustomId(buildTicketButtonId(interaction.guildId, panelId, i + idx))
                .setLabel(label.slice(0, 80))
                .setStyle(ButtonStyle.Primary)
            );
          });
          rows.push(row);
        }
        await interaction.reply({ content: "Ticket embed sent.", ephemeral: true });
        await interaction.channel.send({ embeds: [embed], components: rows });
        return;
      }
      if (commandName === "purge-all-ticket") {
        const buttonName = String(interaction.options.getString("button_name", true) || "").trim().toLowerCase();
        const cfg = getTicketGuildCfg(interaction.guildId);
        const targets = Object.entries(settings.ticketBot.ticketChannels || {}).filter(
          ([, meta]) =>
            meta.guildId === interaction.guildId &&
            String(meta.buttonName || "").trim().toLowerCase() === buttonName
        );
        let deleted = 0;
        for (const [channelId] of targets) {
          const ch = interaction.guild.channels.cache.get(channelId) || (await interaction.guild.channels.fetch(channelId).catch(() => null));
          if (ch) {
            await ch.delete("purge-all-ticket");
            deleted += 1;
          }
          delete settings.ticketBot.ticketChannels[channelId];
        }
        await persistSettings();
        await interaction.reply({ content: `Deleted ${deleted} ticket channel(s) for "${buttonName}".`, ephemeral: true });
        return;
      }
      if (commandName === "close-ticket") {
        if (!interaction.channelId || !interaction.guildId) {
          await interaction.reply({ content: "Use this command in a server channel.", ephemeral: true });
          return;
        }
        const meta = settings.ticketBot.ticketChannels[interaction.channelId];
        if (!meta || meta.guildId !== interaction.guildId) {
          await interaction.reply({ content: "This channel is not a ticket created by the bot.", ephemeral: true });
          return;
        }
        const ver = getTicketGuildVerification(interaction.guildId);
        const isOwner = meta.ownerId === interaction.user.id;
        const isSupport = !!(ver && ver.roleId && memberHasRole(interaction, ver.roleId));
        if (!isOwner && !isSupport) {
          await interaction.reply({ content: "You cannot close this ticket.", ephemeral: true });
          return;
        }
        await interaction.reply({ content: "Closing ticket...", ephemeral: true });
        delete settings.ticketBot.ticketChannels[interaction.channelId];
        await persistSettings();
        if (interaction.channel) {
          await interaction.channel.delete("close-ticket command");
        }
        return;
      }
      if (commandName === "blacklist") {
        const user = interaction.options.getUser("user", false);
        const fallbackUserId = String(interaction.options.getString("user_id", false) || "").replace(/\D/g, "");
        const targetUserId = user?.id || fallbackUserId;
        if (!targetUserId) {
          await interaction.reply({ content: "Provide a user or user_id.", ephemeral: true });
          return;
        }
        const blacklist = getTicketBlacklistMap(interaction.guildId);
        blacklist[targetUserId] = {
          userId: targetUserId,
          username: user?.username || "",
          blacklistedAt: Date.now(),
          byUserId: interaction.user.id,
        };
        await persistSettings();
        await interaction.reply({ content: `Blacklisted <@${targetUserId}> from creating tickets.`, ephemeral: true });
        return;
      }
      if (commandName === "unblacklist") {
        const user = interaction.options.getUser("user", false);
        const fallbackUserId = String(interaction.options.getString("user_id", false) || "").replace(/\D/g, "");
        const targetUserId = user?.id || fallbackUserId;
        if (!targetUserId) {
          await interaction.reply({ content: "Provide a user or user_id.", ephemeral: true });
          return;
        }
        const blacklist = getTicketBlacklistMap(interaction.guildId);
        if (!blacklist[targetUserId]) {
          await interaction.reply({ content: `<@${targetUserId}> is not blacklisted.`, ephemeral: true });
          return;
        }
        delete blacklist[targetUserId];
        await persistSettings();
        await interaction.reply({ content: `Removed <@${targetUserId}> from ticket blacklist.`, ephemeral: true });
        return;
      }
      if (commandName === "show-blacklisted-list") {
        const blacklist = getTicketBlacklistMap(interaction.guildId);
        const rows = Object.values(blacklist || {});
        if (!rows.length) {
          await interaction.reply({ content: "Blacklist is empty.", ephemeral: true });
          return;
        }
        const message = rows
          .slice(0, 50)
          .map((item, idx) => `${idx + 1}. ${item.username ? `${item.username} ` : ""}(<@${item.userId}>)`)
          .join("\n");
        await interaction.reply({ content: `Blacklisted Users:\n${message}`, ephemeral: true });
        return;
      }
    } catch (err) {
      try {
        if (!interaction.replied && !interaction.deferred) {
          await interaction.reply({ content: "Ticket bot command failed.", ephemeral: true });
        }
      } catch (e) {}
    }
  });
  try {
    await registerTicketBotCommands(token, appId);
    await client.login(token);
  } catch (err) {
    console.error("[TicketBot] failed to start:", err.message);
    await stopTicketBot();
  }
}

// --- Settings ---
app.get("/api/jx/settings", requireAuth, (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot access settings" });
  }
  res.json({ ok: true, settings });
});

app.post("/api/jx/settings", requireAuth, (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot modify settings" });
  }
  const {
    prefix,
    checkpoints,
    generateLimit,
    expirationHours,
    addTimeHours,
    startCooldownMinutes,
    plusTimeCooldownHours,
    plusTimeUsesBeforeCooldown,
    testKeyHours,
    tokenLimit,
    tokenLimitGenerateKey,
    tokenLimitExtendKey,
    tokenLimitToBuy,
    keyless,
    guestEnabled,
    antiBypass,
    antiExtension,
    bindPremiumKey,
    boostMode,
    tutorial,
    bot,
    ticketBot,
  } = req.body || {};
  if (prefix) settings.prefix = prefix.trim();
  if (checkpoints) settings.checkpoints = Number(checkpoints);
  if (generateLimit) settings.generateLimit = Math.max(1, Number(generateLimit) || 3);
  if (expirationHours) settings.expirationHours = Number(expirationHours);
  if (addTimeHours) settings.addTimeHours = Math.max(1, Number(addTimeHours) || 12);
  if (startCooldownMinutes) settings.startCooldownMinutes = Math.max(1, Number(startCooldownMinutes) || 5);
  if (plusTimeCooldownHours) settings.plusTimeCooldownHours = Math.max(1, Number(plusTimeCooldownHours) || 12);
  if (plusTimeUsesBeforeCooldown) settings.plusTimeUsesBeforeCooldown = Math.max(1, Number(plusTimeUsesBeforeCooldown) || 2);
  if (testKeyHours) settings.testKeyHours = Math.max(1, Number(testKeyHours) || 48);
  if (typeof tokenLimit !== "undefined") settings.tokenLimit = Math.max(1, Number(tokenLimit) || 3);
  if (typeof tokenLimitGenerateKey !== "undefined") settings.tokenLimitGenerateKey = Math.max(0, Number(tokenLimitGenerateKey) || 0);
  if (typeof tokenLimitExtendKey !== "undefined") settings.tokenLimitExtendKey = Math.max(0, Number(tokenLimitExtendKey) || 0);
  if (typeof tokenLimitToBuy !== "undefined") settings.tokenLimitToBuy = Math.max(1, Number(tokenLimitToBuy) || 9);
  if (typeof keyless !== "undefined") settings.keyless = keyless === true || keyless === "true";
   if (typeof guestEnabled !== "undefined") settings.guestEnabled = guestEnabled === true || guestEnabled === "true";
  if (typeof antiBypass !== "undefined") settings.antiBypass = antiBypass === true || antiBypass === "true";
  if (typeof antiExtension !== "undefined") settings.antiExtension = antiExtension === true || antiExtension === "true";
  if (typeof bindPremiumKey !== "undefined") settings.bindPremiumKey = bindPremiumKey === true || bindPremiumKey === "true";
  if (boostMode && typeof boostMode === "object") {
    settings.boostMode = {
      enabled: !!boostMode.enabled,
      likeUrl: (boostMode.likeUrl || "").trim(),
      subscribeUrl: (boostMode.subscribeUrl || "").trim(),
      discordUrl: (boostMode.discordUrl || "").trim(),
    };
  }
  if (tutorial && typeof tutorial === "object") {
    settings.tutorial = {
      enabled: !!tutorial.enabled,
      url: normalizeTutorialUrl(tutorial.url),
    };
  }
  if (bot && typeof bot === "object") {
    ensureBotSettings();
    const prevActivation = settings.bot.activationToken;
    settings.bot.token = normalizeDiscordToken(bot.token);
    settings.bot.appId = String(bot.appId || settings.bot.appId || "").trim();
    settings.bot.activationToken = (bot.activationToken || settings.bot.activationToken || randActivationToken()).trim();
    settings.bot.verifiedGuilds = bot.verifiedGuilds && typeof bot.verifiedGuilds === "object" ? bot.verifiedGuilds : settings.bot.verifiedGuilds;
    if (prevActivation && settings.bot.activationToken !== prevActivation) {
      settings.bot.verifiedGuilds = {};
    }
  } else {
    ensureBotSettings();
  }
  if (ticketBot && typeof ticketBot === "object") {
    ensureBotSettings();
    const prevActivation = settings.ticketBot.activationToken;
    settings.ticketBot.token = normalizeDiscordToken(ticketBot.token);
    settings.ticketBot.appId = String(ticketBot.appId || settings.ticketBot.appId || "").trim();
    settings.ticketBot.activationToken = (ticketBot.activationToken || settings.ticketBot.activationToken || randActivationToken()).trim();
    settings.ticketBot.verifiedGuilds =
      ticketBot.verifiedGuilds && typeof ticketBot.verifiedGuilds === "object"
        ? ticketBot.verifiedGuilds
        : settings.ticketBot.verifiedGuilds;
    settings.ticketBot.guildConfig =
      ticketBot.guildConfig && typeof ticketBot.guildConfig === "object"
        ? ticketBot.guildConfig
        : settings.ticketBot.guildConfig;
    settings.ticketBot.ticketChannels =
      ticketBot.ticketChannels && typeof ticketBot.ticketChannels === "object"
        ? ticketBot.ticketChannels
        : settings.ticketBot.ticketChannels;
    settings.ticketBot.blacklistedUsers =
      ticketBot.blacklistedUsers && typeof ticketBot.blacklistedUsers === "object"
        ? ticketBot.blacklistedUsers
        : settings.ticketBot.blacklistedUsers;
    if (prevActivation && settings.ticketBot.activationToken !== prevActivation) {
      settings.ticketBot.verifiedGuilds = {};
    }
  } else {
    ensureBotSettings();
  }
  if (useDb) dbUpsert(mongoCfg.colSettings, "settings", { settings });
  refreshDiscordBot().catch(() => {});
  refreshTicketBot().catch(() => {});
  res.json({ ok: true, settings });
});

app.post("/api/jx/keys/manual-activate", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot manually activate premium keys" });
  }
  const keyValue = qstr(req.body?.key);
  const userId = qstr(req.body?.userId).replace(/\D/g, "");
  if (!keyValue || !userId) {
    return res.status(400).json({ ok: false, message: "Premium key and user ID are required" });
  }
  const result = await bindPremiumKeyToDiscord({ keyValue, userId });
  if (!result.ok) {
    return res.status(400).json({ ok: false, message: result.message || "Activation failed" });
  }
  return res.json({
    ok: true,
    key: result.key?.key || keyValue,
    userId: result.key?.discordUserId || userId,
  });
});

app.post("/api/jx/bot/regenerate-activation", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot regenerate activation token" });
  }
  ensureBotSettings();
  settings.bot.activationToken = randActivationToken();
  settings.bot.verifiedGuilds = {};
  await persistSettings();
  return res.json({ ok: true, activationToken: settings.bot.activationToken });
});

app.post("/api/jx/ticket-bot/regenerate-activation", requireAuth, async (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot regenerate activation token" });
  }
  ensureBotSettings();
  settings.ticketBot.activationToken = randActivationToken();
  settings.ticketBot.verifiedGuilds = {};
  await persistSettings();
  return res.json({ ok: true, activationToken: settings.ticketBot.activationToken });
});

// --- Requests listing ---
app.get("/api/jx/requests", requireAuth, (req, res) => {
  if (req.session?.role === "guest") {
    return res.status(403).json({ ok: false, message: "Guest cannot view requests" });
  }
  cleanup();
  res.json({
    ok: true,
    requests: Array.from(requests.entries()).map(([id, r]) => ({
      id,
      hwid: r.hwid,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
    })),
  });
});

// Keep bots healthy even after transient gateway/network drops.
setInterval(() => {
  refreshDiscordBot().catch(() => {});
  refreshTicketBot().catch(() => {});
}, 60 * 1000);

// --- Start server ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ JX Key System server running on ${PORT}`);
  console.log("🔗 Dashboard: /dashboard | Login: /login");
});
