const express = require("express");
const fs = require("fs");
const path = require("path");
const bodyParser = require("body-parser");
const Web3 = require("web3").default;

// === App & Middleware ===
const app = express();
const PORT = 3000;

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public")));

// === Load Local DB ===
const DB_PATH = path.join(__dirname, "database.json");
let db = { users: [] };
if (fs.existsSync(DB_PATH)) {
  db = JSON.parse(fs.readFileSync(DB_PATH));
}

// === Blockchain Setup ===
const web3 = new Web3(
  "https://sepolia.infura.io/v3/b38cf753021449a584d8a9ea94fce34c",
);
const contractABI = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "rfid",
        type: "string",
      },
    ],
    name: "addUser",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
  {
    inputs: [],
    name: "admin",
    outputs: [
      {
        internalType: "address",
        name: "",
        type: "address",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "rfid",
        type: "string",
      },
    ],
    name: "isUser",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
  {
    inputs: [
      {
        internalType: "string",
        name: "",
        type: "string",
      },
    ],
    name: "validRFIDs",
    outputs: [
      {
        internalType: "bool",
        name: "",
        type: "bool",
      },
    ],
    stateMutability: "view",
    type: "function",
  },
];
const contractAddress = "0x71e3Fc38c65e28730162D072b85636b4207710FE";
const contract = new web3.eth.Contract(contractABI, contractAddress);

// === Serve Pages ===
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "views/index.html"));
});

app.get("/dashboard", (req, res) => {
  res.sendFile(path.join(__dirname, "views/dashboard.html"));
});

// === ESP8266 RFID + Password Authentication ===
app.post("/authenticate", async (req, res) => {
  try {
    const { rfid, password } = req.body;

    if (!rfid || !password) {
      return res
        .status(400)
        .json({ success: false, msg: "Missing RFID or password" });
    }

    // Check local DB for user
    const user = db.users.find((u) => u.rfid === rfid);

    if (!user) {
      return res.status(404).json({ success: false, msg: "RFID not found" });
    }

    if (!user.password) {
      // First-time password setup
      user.password = password;
      fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
      return res.json({
        success: true,
        msg: "Password initialized. Continue with MetaMask login.",
      });
    }

    if (user.password !== password) {
      return res.status(403).json({ success: false, msg: "Invalid password" });
    }

    // Check if RFID is registered on blockchain
    const isRegistered = await contract.methods.isUser(rfid).call();

    if (!isRegistered) {
      return res
        .status(403)
        .json({ success: false, msg: "RFID not registered on blockchain" });
    }

    res.json({
      success: true,
      msg: "Authentication successful. Proceed to blockchain login.",
    });
  } catch (err) {
    console.error("Authentication Error:", err);
    res.status(500).json({ success: false, msg: "Server error" });
  }
});

// === Start Server ===
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
