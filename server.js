// server.js
require("dotenv").config();
const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const bodyParser = require("body-parser");
const session = require("express-session");
const { ethers, utils } = require("ethers");

// --- Config ---
const {
  PORT = 3000,
  SESSION_SECRET = "dev-secret-change-me",
  RPC_URL,
  CONTRACT_ADDRESS,
  PRIVATE_KEY,
  WALLET_ONLY_WINDOW = 350, // seconds (wallet-only after this)
  FULL_RELOGIN_WINDOW = 900 // seconds (full-login after this)
} = process.env;

if (!RPC_URL || !CONTRACT_ADDRESS || !PRIVATE_KEY) {
  console.warn("[WARN] Missing RPC_URL / CONTRACT_ADDRESS / PRIVATE_KEY");
}

// --- Load ABI ---
const abi = require("./abi/ContractABI.json");

// --- Ethers v6 setup ---
let provider, signer, contract;
try {
  // Ethers v6: JsonRpcProvider is on root
  provider = new ethers.providers.JsonRpcProvider(RPC_URL);
  signer = new ethers.Wallet(PRIVATE_KEY, provider);
  contract = new ethers.Contract(CONTRACT_ADDRESS, abi, signer);
  console.log("[OK] Connected to blockchain");
} catch (err) {
  console.error("[ERROR] Ethers setup failed:", err);
}

// --- JSON store ---
const DB_FILE = path.join(__dirname, "database.json");
function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
  } catch {
    return { sessionsAddr: {}, walletBindings: {} }; // sessions keyed by wallet address (lowercase), bindings: rfidHash -> wallet
  }
}
function writeDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}
const db = readDB();
db.sessionsAddr ||= {};
db.walletBindings ||= {};

// --- App ---
const app = express();
app.use(cors({ origin: true, credentials: true }));
app.use(bodyParser.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "none", // set "lax" if same-origin; for cross-site cookies, "none" + secure:true over HTTPS
      secure: false     // set to true when your site is on HTTPS
    }
  })
);
app.use(express.static(path.join(__dirname, "public")));

const nowSec = () => Math.floor(Date.now() / 1000);

// Helpers
const hashUtf8 = (s) => utils.keccak256(utils.toUtf8Bytes(s));

const zeroAddr = ethers.ZeroAddress;

function getOrInitAddrSession(address) {
  const a = address.toLowerCase();
  db.sessionsAddr[a] ||= {
    lastWalletAuthAt: 0,
    lastFullAuthAt: 0
  };
  return db.sessionsAddr[a];
}

function rfidByAddress(address) {
  const a = address.toLowerCase();
  for (const [rfidHash, wallet] of Object.entries(db.walletBindings)) {
    if (wallet && wallet.toLowerCase() === a) return rfidHash;
  }
  return null;
}

function policyResult(sess) {
  const t = nowSec();
  const needFull = (t - sess.lastFullAuthAt) >= Number(FULL_RELOGIN_WINDOW);
  const needWalletOnly = !needFull && (t - sess.lastWalletAuthAt) >= Number(WALLET_ONLY_WINDOW);
  return { needFull, needWalletOnly };
}

// === ESP8266: RFID + PIN ===
// Body: { rfid: "string", password: "string" }
app.post("/authenticate", async (req, res) => {
  try {
    const { rfid, password } = req.body || {};
    if (!rfid || !password) {
      return res.status(400).json({ ok: false, error: "bad-request" });
    }

    const rfidHash = hashUtf8(rfid);
    const passHash = hashUtf8(password);

    // Read user from chain
    const [exists, hasPassword, wallet] = await contract.getUser(rfidHash);
    if (!exists) {
      return res.status(401).json({ ok: false, error: "not-registered" });
    }

    let valid = false;

    if (!hasPassword) {
      // First-time password set (admin-only tx)
      try {
        const tx = await contract.setPasswordFirstTime(rfidHash, passHash);
        await tx.wait();
        valid = true;
      } catch (e) {
        console.error("setPasswordFirstTime failed:", e);
        return res.status(500).json({ ok: false, error: "set-password-failed" });
      }
    } else {
      // Normal verification
      try {
        valid = await contract.verifyCredentials(rfidHash, passHash);
      } catch (e) {
        console.error("verifyCredentials failed:", e);
        return res.status(500).json({ ok: false, error: "contract-call-failed" });
      }
    }

    if (!valid) {
      return res.status(401).json({ ok: false, error: "invalid-credentials" });
    }

    // If RFID already has a bound wallet, mark a full-auth against that wallet
    const boundWallet = wallet && wallet !== zeroAddr ? wallet : null;
    if (boundWallet) {
      const sess = getOrInitAddrSession(boundWallet);
      const t = nowSec();
      sess.lastFullAuthAt = t;
      sess.lastWalletAuthAt = t;
      // Ensure DB binding knows about it too
      db.walletBindings[rfidHash] = boundWallet;
      writeDB(db);
    }

    const next = boundWallet ? "none" : "wallet";
    return res.json({
      ok: true,
      rfidHash,
      boundWallet,
      next
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

/**
 * Body: { address, signature, rfidHash? }
 * - If wallet already bound (found in db.walletBindings via reverse lookup), rfidHash is optional.
 * - If not bound yet, provide rfidHash from the *most recent* successful /authenticate (frontend should carry it forward).
 */
app.post("/siwe/verify", async (req, res) => {
  console.log(req.body);
  try {
    const { address, signature, rfidHash } = req.body || {};
    let nonce = req.session.nonce;
    if (!nonce) {
      nonce = crypto.randomBytes(16).toString("hex");
      req.session.nonce = nonce;
      console.warn("[WARN] Nonce was missing, generated new:", nonce);
    }
    console.log("Nonce:", nonce);
    if (!nonce || !address || !signature) {
      return res.status(400).json({ ok: false, error: "bad-request" });
    }

    // Verify SIWE message
    const message = `Login to ZeroTrust - nonce:${nonce}`;
    const recovered = ethers.utils.verifyMessage(message, signature);
    if (recovered.toLowerCase() !== address.toLowerCase()) {
      return res.status(401).json({ ok: false, error: "bad-signature" });
    }

    const addrL = address.toLowerCase();
    const sess = getOrInitAddrSession(addrL);

    // Resolve RFID to bind/use
    let resolvedRfid = rfidByAddress(addrL); // if already bound
    const firstBind = !resolvedRfid;

    if (firstBind) {
      if (!rfidHash) {
        return res.status(400).json({ ok: false, error: "rfid-required-for-first-bind" });
      }
      // Bind on-chain (admin-only)
      try {
        const tx = await contract.bindWallet(rfidHash, address);
        await tx.wait();
        db.walletBindings[rfidHash] = address;
        resolvedRfid = rfidHash;
        writeDB(db);
      } catch (e) {
        console.error("bindWallet failed:", e);
        return res.status(500).json({ ok: false, error: "bind-failed" });
      }
      // First-time binding counts as a "full" event in this prototype
      const t = nowSec();
      sess.lastFullAuthAt = t;
      sess.lastWalletAuthAt = t;
      writeDB(db);
    } else {
      // Just a wallet auth refresh
      sess.lastWalletAuthAt = nowSec();
      writeDB(db);
    }

    // Keep wallet in session for policy checks from browser
    req.session.address = addrL;

    return res.json({ ok: true, address: addrL, rfidHash: resolvedRfid, firstBind });
  } catch (e) {
    console.error("/siwe/verify error:", e);
    res.status(500).json({ ok: false, error: "server-error" });
  }
});

// === Policy check (uses wallet address only) ===
app.get("/reauth-policy", (req, res) => {
  const addrL = req.session.address;
  if (!addrL) {
    // No wallet session -> needs full login
    return res.json({ needFull: true, needWalletOnly: false });
  }
  const sess = getOrInitAddrSession(addrL);
  res.json(policyResult(sess));
});

// === Dashboard state (uses wallet address only) ===
app.get("/api/dashboard-state", async (req, res) => {
  const addrL = req.session.address;
  if (!addrL) return res.status(401).json({ ok: false, error: "no-session" });

  const sess = getOrInitAddrSession(addrL);
  const pol = policyResult(sess);

  if (pol.needFull)  return res.status(401).json({ ok: false, error: "need-full" });
  if (pol.needWalletOnly) return res.status(401).json({ ok: false, error: "need-wallet" });

  const rfidHash = rfidByAddress(addrL);
  res.json({ ok: true, address: addrL, rfidHash });
});

// === Pages ===
app.get("/login", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);
app.get("/dashboard", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "dashboard.html"))
);

app.listen(PORT, () => {
  console.log(`Zero-Trust server running on http://localhost:${PORT}`);
});
