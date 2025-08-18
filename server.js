// server.js
require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const session = require("express-session");
const { ethers } = require("ethers");

// --- Config ---
const {
  PORT = 3000,
  SESSION_SECRET,
  RPC_URL,
  CONTRACT_ADDRESS,
  PRIVATE_KEY,
  WALLET_ONLY_WINDOW = 60,
  FULL_RELOGIN_WINDOW = 90,
} = process.env;

if (!RPC_URL || !CONTRACT_ADDRESS || !PRIVATE_KEY) {
  console.warn("[WARN] Missing RPC_URL / CONTRACT_ADDRESS / PRIVATE_KEY");
}

// --- Load ABI ---
const abi = require("./abi/ContractABI.json"); // export from Remix for ZeroTrustAuth

// --- Ethers setup ---
let provider, signer, contract;
try {
  provider = new ethers.JsonRpcProvider(RPC_URL); //  Correct constructor for ethers v6
  signer = new ethers.Wallet(PRIVATE_KEY, provider);
  contract = new ethers.Contract(CONTRACT_ADDRESS, abi, signer);
  console.log("[OK] Connected to blockchain");
} catch (err) {
  console.error("[ERROR] Ethers setup failed:", err.message);
}

// --- JSON store ---
const DB_FILE = path.join(__dirname, "database.json");
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { sessions: {}, walletBindings: {} };
  }
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
const db = readDB();

// --- App ---
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: "lax" },
  }),
);
app.use(express.static(path.join(__dirname, "public")));

const nowSec = () => Math.floor(Date.now() / 1000);

// Helpers
const hashUtf8 = (s) => ethers.keccak256(ethers.utils.toUtf8Bytes(s));

function getOrInitSession(userKey /* rfidHash hex */, req) {
  db.sessions[userKey] ||= {
    lastWalletAuthAt: 0,
    lastFullAuthAt: 0,
    boundWallet: db.walletBindings[userKey] || null,
    rfidHash: userKey,
  };
  req.session.userKey = userKey;
  req.session.boundWallet = db.sessions[userKey].boundWallet;
  writeDB(db);
  return db.sessions[userKey];
}
function policyResult(sess) {
  const t = nowSec();
  const needFull = t - sess.lastFullAuthAt >= Number(FULL_RELOGIN_WINDOW);
  const needWalletOnly =
    !needFull && t - sess.lastWalletAuthAt >= Number(WALLET_ONLY_WINDOW);
  return { needFull, needWalletOnly };
}

// === ESP8266: RFID + PIN ===
app.post("/authenticate", async (req, res) => {
  try {
    const { rfid, password } = req.body || {};
    if (!rfid || !password)
      return res.status(400).json({ ok: false, error: "bad-request" });

    const rfidHash = hashUtf8(rfid);
    const passHash = hashUtf8(password);

    // Read user from chain
    const [exists, hasPassword, wallet] = await contract.getUser(rfidHash);
    if (!exists)
      return res.status(401).json({ ok: false, error: "not-registered" });

    let valid = false;

    if (!hasPassword) {
      // First-time password set
      try {
        const tx = await contract.setPasswordFirstTime(rfidHash, passHash);
        await tx.wait();
        valid = true;
      } catch (e) {
        console.error("setPasswordFirstTime failed:", e.message);
        return res
          .status(500)
          .json({ ok: false, error: "set-password-failed" });
      }
    } else {
      // Normal verification
      try {
        valid = await contract.verifyCredentials(rfidHash, passHash);
      } catch (e) {
        console.error("verifyCredentials failed:", e.message);
        return res
          .status(500)
          .json({ ok: false, error: "contract-call-failed" });
      }
    }

    if (!valid)
      return res.status(401).json({ ok: false, error: "invalid-credentials" });

    // Update session
    const sess = getOrInitSession(rfidHash, req);
    const t = nowSec();
    sess.lastFullAuthAt = t;
    sess.lastWalletAuthAt = t;
    sess.boundWallet = wallet && wallet !== ethers.ZeroAddress ? wallet : null;
    if (sess.boundWallet) db.walletBindings[rfidHash] = sess.boundWallet;
    writeDB(db);

    const next = sess.boundWallet ? "none" : "wallet";
    return res.json({
      ok: true,
      userId: rfid,
      rfidHash,
      boundWallet: sess.boundWallet,
      next,
    });
  } catch (e) {
    console.error("/authenticate error:", e);
    return res.status(500).json({ ok: false, error: "server-error" });
  }
});

// === SIWE-style wallet login ===
app.get("/siwe/nonce", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("hex");
  req.session.nonce = nonce;
  res.json({ nonce });
});

app.post("/siwe/verify", async (req, res) => {
  try {
    const { address, signature } = req.body || {};
    const nonce = req.session.nonce;
    const userKey = req.session.userKey;

    if (!nonce || !address || !signature || !userKey) {
      return res.status(400).json({ ok: false, error: "bad-request" });
    }

    const message = `Login to ZeroTrust - nonce:${nonce}`;
    const recovered = ethers.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== address.toLowerCase())
      return res.status(401).json({ ok: false, error: "bad-signature" });

    const sess = getOrInitSession(userKey, req);

    if (!sess.boundWallet) {
      try {
        const tx = await contract.bindWallet(userKey, address);
        await tx.wait();
        sess.boundWallet = address;
        db.walletBindings[userKey] = address;
      } catch (e) {
        console.error("bindWallet failed:", e.message);
        return res.status(500).json({ ok: false, error: "bind-failed" });
      }
    }

    sess.lastWalletAuthAt = nowSec();
    req.session.address = address;
    writeDB(db);
    return res.json({ ok: true, address, userKey });
  } catch (e) {
    console.error("/siwe/verify error:", e);
    res.status(500).json({ ok: false, error: "server-error" });
  }
});

// === Policy check ===
app.get("/reauth-policy", (req, res) => {
  const userKey = req.session.userKey;
  if (!userKey) return res.json({ needFull: true, needWalletOnly: false });
  const sess = getOrInitSession(userKey, req);
  res.json({ ...policyResult(sess) });
});

app.get("/api/dashboard-state", async (req, res) => {
  const userKey = req.session.userKey;
  if (!userKey) return res.status(401).json({ ok: false, error: "no-session" });
  const sess = getOrInitSession(userKey, req);
  const pol = policyResult(sess);
  if (pol.needFull)
    return res.status(401).json({ ok: false, error: "need-full" });
  if (pol.needWalletOnly)
    return res.status(401).json({ ok: false, error: "need-wallet" });
  res.json({ ok: true, userKey, boundWallet: sess.boundWallet });
});

// === Pages ===
app.get("/login", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html")),
);
app.get("/dashboard", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "dashboard.html")),
);

app.listen(PORT, () => {
  console.log(`Zero-Trust server running on http://localhost:${PORT}`);
});
