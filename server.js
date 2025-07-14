const express = require("express");
const cors = require("cors");
const fs = require("fs");
const bodyParser = require("body-parser");
const Web3 = require("web3").default;
const path = require("path");

const app = express();
const port = 3000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, "public"))); // Serve frontend

// === Web3 Setup ===
const web3 = new Web3(
  new Web3.providers.HttpProvider(
    "https://sepolia.infura.io/v3/b38cf753021449a584d8a9ea94fce34c",
  ),
);
const contractABI = [
  {
    inputs: [],
    stateMutability: "nonpayable",
    type: "constructor",
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
    name: "isRegistered",
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
        name: "rfid",
        type: "string",
      },
    ],
    name: "registerRFID",
    outputs: [],
    stateMutability: "nonpayable",
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
    name: "removeRFID",
    outputs: [],
    stateMutability: "nonpayable",
    type: "function",
  },
];
const contractAddress = "0x0e231E96D288F7a8e96cC01C3E194CEcb7Ad8F13"; // deployed contract
const contract = new web3.eth.Contract(contractABI, contractAddress);

// === Database ===
const dbPath = "./database.json";
function loadDatabase() {
  if (!fs.existsSync(dbPath)) return {};
  return JSON.parse(fs.readFileSync(dbPath));
}
function saveDatabase(data) {
  fs.writeFileSync(dbPath, JSON.stringify(data, null, 2));
}

// === Authenticate (IoT Flow) ===
app.post("/authenticate", async (req, res) => {
  const { rfid, password } = req.body;
  const db = loadDatabase();

  if (!rfid || !password)
    return res
      .status(400)
      .json({ success: false, message: "Missing credentials" });

  const isRegistered = await contract.methods.isRegistered(rfid).call();
  if (!isRegistered || !db[rfid] || db[rfid].password !== password) {
    return res
      .status(403)
      .json({ success: false, message: "Authentication failed" });
  }

  return res
    .status(200)
    .json({ success: true, message: "Authentication successful" });
});

// === Set password (IoT first use) ===
app.post("/set-password", (req, res) => {
  const { rfid, password } = req.body;
  const db = loadDatabase();
  db[rfid] = { password };
  saveDatabase(db);
  res.status(200).json({ success: true });
});

// === Register RFID via smart contract ===
app.post("/register-rfid", async (req, res) => {
  const { rfid, fromAddress } = req.body;
  try {
    const tx = await contract.methods
      .registerRFID(rfid)
      .send({ from: fromAddress });
    res.status(200).json({ success: true, tx });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Smart contract error",
      error: err.message,
    });
  }
});

app.listen(port, () =>
  console.log(`Server running at http://localhost:${port}`),
);
