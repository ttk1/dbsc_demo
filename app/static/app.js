let pollTimer = null;

async function doLogin() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;

  try {
    const res = await fetch("/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    if (!res.ok) {
      alert("Login failed");
      return;
    }
    document.getElementById("login-section").classList.add("hidden");
    document.getElementById("status-section").classList.remove("hidden");
    startPolling();
  } catch (e) {
    alert("Login error: " + e.message);
  }
}

async function doLogout() {
  await fetch("/logout", { method: "POST" });
  document.getElementById("login-section").classList.remove("hidden");
  document.getElementById("status-section").classList.add("hidden");
  stopPolling();
}

async function pollStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    const authEl = document.getElementById("auth-status");
    authEl.textContent = data.authenticated ? "Yes" : "No";
    authEl.className = "value " + (data.authenticated ? "ok" : "warn");

    document.getElementById("session-id").textContent = data.session_id || "--";

    const cookieEl = document.getElementById("cookie-status");
    cookieEl.textContent = data.cookie_present ? "Yes" : "No (expired)";
    cookieEl.className = "value " + (data.cookie_present ? "ok" : "warn");
  } catch (_) {}
}

function startPolling() {
  pollStatus();
  pollTimer = setInterval(pollStatus, 2000);
}

function stopPolling() {
  clearInterval(pollTimer);
  pollTimer = null;
}

// Auto-start polling if already logged in (page reload)
if (!document.getElementById("status-section").classList.contains("hidden")) {
  startPolling();
}
