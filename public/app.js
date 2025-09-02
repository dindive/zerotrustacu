async function getJSON(url) {
  const r = await fetch(url, { credentials: "include" });
  return r.json();
}
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify(body),
  });
  return r.json();
}

// UI helpers
const el = (id) => document.getElementById(id);
function log(msg) {
  const l = el("log");
  if (l) l.innerHTML = msg;
}

// Policy indicator on index page
async function refreshPolicyTag() {
  if (!el("policy")) return;
  const pol = await getJSON("/reauth-policy");
  let text = "fresh";
  if (pol.needFull) text = "full login required";
  else if (pol.needWalletOnly) text = "wallet re-auth";
  el("policy").textContent = text;
}

// Wallet button present on both pages
const btn = el("btnWallet");
if (btn) {
  btn.onclick = async () => {
    if (!window.ethereum) return log("No wallet found. Install MetaMask.");
    const [addr] = await window.ethereum.request({
      method: "eth_requestAccounts",
    });
    const { nonce } = await getJSON("/siwe/nonce");
    const message = `Login to ZeroTrust - nonce:${nonce}`;
    const sig = await window.ethereum.request({
      method: "personal_sign",
      params: [message, addr],
    });
    const res = await postJSON("/siwe/verify", {
      address: addr,
      signature: sig,
    });
    if (res.ok) {
      log?.("Wallet verified ✅");
      // If on login page, go to dashboard
      window.location.href = "https://zerotrustacu.onrender.com/dashboard.html";
      else loadDashboard();
    } else {
      log?.(`Wallet verify failed: ${res.error || "unknown"}`);
    }
  };
}

// Dashboard polling
async function loadDashboard() {
  const stateEl = el("state");
  const statusEl = el("status");
  try {
    const resp = await getJSON("/api/dashboard-state");
    if (resp.ok) {
      stateEl.textContent = `User: ${resp.userId} | Bound wallet: ${
        resp.boundWallet || "none"
      }`;
      statusEl.textContent = "Session OK";
      statusEl.className = "ok";
    } else {
      if (resp.error === "need-wallet") {
        statusEl.textContent = "Wallet re-auth required";
        statusEl.className = "warn";
      } else if (resp.error === "need-full") {
        statusEl.textContent =
          "Full re-login required (tap RFID + PIN on terminal)";
        statusEl.className = "bad";
      } else {
        statusEl.textContent = "Not authenticated";
        statusEl.className = "bad";
      }
    }
  } catch (e) {
    stateEl.textContent = "Error loading state";
  }
}

if (location.pathname.includes("/dashboard")) {
  loadDashboard();
  setInterval(loadDashboard, 5000); // periodic policy enforcement
}
if (location.pathname.includes("/login")) {
  refreshPolicyTag();
  setInterval(refreshPolicyTag, 5000);
}
