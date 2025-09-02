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
  SESSION_SECRET = "dev-secret-change-me",
  RPC_URL,
  CONTRACT_ADDRESS,
  PRIVATE_KEY,
  WALLET_ONLY_WINDOW = 350, // seconds
  FULL_RELOGIN_WINDOW = 900 // seconds
} = process.env;

if (!RPC_URL || !CONTRACT_ADDRESS || !PRIVATE_KEY) {
  console.warn("[WARN] Missing RPC_URL / CONTRACT_ADDRESS / PRIVATE_KEY");
}

// --- Load ABI ---
const abi = require("./abi/ContractABI.json");

// --- Ethers v5 setup ---
let provider, signer, contract;
try {
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
    return { sessionsAddr: {}, walletBindings: {} };
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
    cookie: { httpOnly: true, sameSite: "none", secure: false }
  })
);
app.use(express.static(path.join(__dirname, "public")));

const nowSec = () => Math.floor(Date.now() / 1000);
const hashUtf8 = (s) =>
  ethers.utils.keccak256(ethers.utils.toUtf8Bytes(s));

// --- Helpers ---
function getOrInitAddrSession(address) {
  const a = address.toLowerCase();
  db.sessionsAddr[a] ||= { lastWalletAuthAt: 0, lastFullAuthAt: 0 };
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
  const needWalletOnly =
    !needFull && (t - sess.lastWalletAuthAt) >= Number(WALLET_ONLY_WINDOW);
  return { needFull, needWalletOnly };
}

// === ESP8266: RFID + PIN ===
app.post("/authenticate", async (req, res) => {
  try {
    const { rfid, password } = req.body || {};
    console.log("[/authenticate] payload:", req.body);

    if (!rfid || !password) {
      return res.status(400).json({ ok: false, error: "bad-request" });
    }

    const rfidHash = hashUtf8(rfid);
    const passHash = hashUtf8(password);
    console.log("rfidHash:", rfidHash, "passHash:", passHash);

    // Read user from chain
    const [exists, hasPassword, wallet] = await contract.getUser(rfidHash);
    console.log("contract.getUser ->", { exists, hasPassword, wallet });

    if (!exists) {
      return res.status(401).json({ ok: false, error: "not-registered" });
    }

    let valid = false;

    if (!hasPassword) {
      console.log("First time password setup");
      try {
        const tx = await contract.setPasswordFirstTime(rfidHash, passHash);
        console.log("tx hash:", tx.hash);
        await tx.wait();
        valid = true;
      } catch (e) {
        console.error("setPasswordFirstTime failed:", e);
        return res.status(500).json({ ok: false, error: "set-password-failed" });
      }
    } else {
      console.log("Verifying credentials...");
      try {
        valid = await contract.verifyCredentials(rfidHash, passHash);
      } catch (e) {
        console.error("verifyCredentials failed:", e);
        return res.status(500).json({ ok: false, error: "contract-call-failed" });
      }
    }

    if (!valid) {
      console.log("Invalid RFID/PIN");
      return res.status(401).json({ ok: false, error: "invalid-credentials" });
    }

    if (wallet && wallet !== ethers.constants.AddressZero) {
      const sess = getOrInitAddrSession(wallet);
      const t = nowSec();
      sess.lastFullAuthAt = t;
      sess.lastWalletAuthAt = t;
      db.walletBindings[rfidHash] = wallet; // mirror locally
      writeDB(db);
      console.log("Session updated for wallet:", wallet);
    }

    return res.json({ ok: true, rfidHash, boundWallet: wallet });
  } catch (e) {
    console.error("/authenticate error:", e);
    return res.status(500).json({ ok: false, error: "server-error" });
  }
});

// === SIWE-style wallet login ===
app.get("/siwe/nonce", (req, res) => {
  const nonce = crypto.randomBytes(16).toString("hex");
  req.session.nonce = nonce;
  console.log("session nonnce". req.session.nonce);
  console.log("[/siwe/nonce] nonce:", nonce);
  res.json({ nonce });
});

app.post("/siwe/verify", async (req, res) => {
  try {
    const { address, signature } = req.body || {};
    let nonce = req.session.nonce;
    if (!nonce) {
      nonce = crypto.randomBytes(16).toString("hex");
      req.session.nonce = nonce;
      console.warn("[WARN] Nonce was missing, generated new:", nonce);
    }
    console.log("[/siwe/verify] body:", req.body, "nonce:", nonce);

    if (!nonce || !address || !signature) {
      return res.status(400).json({ ok: false, error: "bad-request" });
    }

    const message = `Login to ZeroTrust - nonce:${nonce}`;
    const recovered = ethers.utils.verifyMessage(message, signature);
    console.log("Recovered address:", recovered);

    if (recovered.toLowerCase() == address.toLowerCase()) {
      return res.status(401).json({ ok: false, error: "bad-signature" });
    }

    const addrL = address.toLowerCase();
    const sess = getOrInitAddrSession(addrL);

    sess.lastWalletAuthAt = nowSec();
    req.session.address = addrL;
    writeDB(db);
    console.log("Wallet session updated:", addrL);

    return res.json({ ok: true, address: addrL, rfidHash: rfidByAddress(addrL) });
  } catch (e) {
    console.error("/siwe/verify error:", e);
    res.status(500).json({ ok: false, error: "server-error" });
  }
});

// === Policy check ===
app.get("/reauth-policy", (req, res) => {
  const addrL = req.session.address;
  console.log("[/reauth-policy] session address:", addrL);
  if (!addrL) return res.json({ needFull: true, needWalletOnly: false });
  res.json(policyResult(getOrInitAddrSession(addrL)));
});

// === Dashboard state ===
app.get("/api/dashboard-state", (req, res) => {
  const addrL = req.session.address;
  console.log("[/dashboard-state] addr:", addrL);
  if (!addrL) return res.status(401).json({ ok: false, error: "no-session" });

  const sess = getOrInitAddrSession(addrL);
  const pol = policyResult(sess);
  if (pol.needFull) return res.status(401).json({ ok: false, error: "need-full" });
  if (pol.needWalletOnly)
    return res.status(401).json({ ok: false, error: "need-wallet" });

  res.json({ ok: true, address: addrL, rfidHash: rfidByAddress(addrL) });
});

// === Pages ===
app.get("/login", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);
app.get("/dashboard", (_, res) =>
  res.sendFile(path.join(__dirname, "public", "dashboard.html"))
);

app.listen(PORT, () =>
  console.log(`Zero-Trust server running on http://localhost:${PORT}`)
);
