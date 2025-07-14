let account = null;
let authStartTime = null;
let interval30, interval90;

async function checkMetaMaskLogin() {
  if (window.ethereum) {
    const accounts = await ethereum.request({ method: "eth_requestAccounts" });
    account = accounts[0];
    sessionStorage.setItem("authAddress", account);
    authStartTime = Date.now();
    window.location.href = "dashboard.html";
  } else {
    alert("MetaMask is not installed.");
  }
}

function startReAuthTimers() {
  interval30 = setInterval(async () => {
    console.log("⏳ 30s check: Confirm wallet address...");
    const accounts = await ethereum.request({ method: "eth_requestAccounts" });
    if (accounts[0] !== sessionStorage.getItem("authAddress")) {
      alert("Wallet mismatch! Re-authenticating...");
      logout();
    }
  }, 30000); // Every 30 seconds

  interval90 = setInterval(() => {
    alert("🔐 Full re-authentication required.");
    logout();
  }, 90000); // Every 90 seconds
}

function logout() {
  clearInterval(interval30);
  clearInterval(interval90);
  sessionStorage.clear();
  window.location.href = "index.html";
}

// === Main Entry Points ===
document.addEventListener("DOMContentLoaded", () => {
  const loginBtn = document.getElementById("loginBtn");
  const logoutBtn = document.getElementById("logoutBtn");

  if (loginBtn) {
    loginBtn.addEventListener("click", checkMetaMaskLogin);
  }

  if (logoutBtn) {
    logoutBtn.addEventListener("click", logout);
    const addr = sessionStorage.getItem("authAddress");
    document.getElementById("userAddress").textContent = "👤 " + addr;
    startReAuthTimers();
  }
});
