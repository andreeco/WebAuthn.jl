
// webauthn_login.js

async function fetchJSON(url, opts = {}) {
  let resp;
  try {
    resp = await fetch(url, opts);
  } catch (err) {
    throw new Error("Network error: " + err);
  }
  if (!resp.ok) {
    // Try to parse meaningful error
    let msg = await resp.text();
    throw new Error(msg || `HTTP ${resp.status}`);
  }
  return await resp.json();
}

/**
 * Main entry point for WebAuthn login.
 * @param {string} usernameInputId  - The id attribute of the username input.
 * @param {string} resultDivId      - The id of the div to show status/errors.
 */
async function startWebAuthnLogin(usernameInputId, resultDivId) {
  const userInput = document.getElementById(usernameInputId);
  const result = document.getElementById(resultDivId);
  result.textContent = "";

  // 1. Feature-detect up front
  if (!window.PublicKeyCredential || !navigator.credentials) {
    result.textContent = "This browser does not support WebAuthn.";
    return;
  }

  const username = userInput.value.trim();
  //if (!username) {
  //  userInput.classList.add("is-invalid");
  // result.textContent = "Please enter your username.";
  // userInput.focus();
  //  return;
  //}
  userInput.classList.remove("is-invalid");

  let btn = event?.target || null;
  if (btn && btn.tagName === "BUTTON") btn.disabled = true;
  try {
    // 2. Fetch login options from server
    let url = "/webauthn/options/login";
    if (username) url += "?username=" + encodeURIComponent(username);
    let reqopts = await fetchJSON(url);
    // 3. Use browser's built-in JSON→Dict parser if available
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
      reqopts = PublicKeyCredential.parseRequestOptionsFromJSON(reqopts);
    } else {
      // fallback for legacy browsers (manual base64 conversion)
      reqopts.challenge = b64urlToBuf(reqopts.challenge);
      if (Array.isArray(reqopts.allowCredentials)) {
        reqopts.allowCredentials = reqopts.allowCredentials.map(c => ({
          ...c,
          id: b64urlToBuf(c.id)
        }));
      }
    }

    // 4. Ask the user for credential via browser
    result.textContent = "Waiting for security key / passkey…";
    const assertion = await navigator.credentials.get({ publicKey: reqopts });

    // 5. Post result back as JSON, shape-matching WebAuthn spec
    // If browser supports .toJSON (most do), use it directly!
    const payload = typeof assertion.toJSON === "function"
      ? assertion.toJSON()
      : {
        id: assertion.id,
        rawId: bufToB64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: bufToB64url(assertion.response.authenticatorData),
          clientDataJSON: bufToB64url(assertion.response.clientDataJSON),
          signature: bufToB64url(assertion.response.signature)
        }
      };

    const csrf = document.querySelector('meta[name="csrf-token"]').content;

    let loginResp = await fetch("/webauthn/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify(payload)
    });

    if (!loginResp.ok) {
      let msg = "Login failed.";
      try {
        const err = await loginResp.json();
        msg = err?.error || msg;
      } catch (_) { /* fallback to text */ }
      result.textContent = msg;
      return;
    }

    const body = await loginResp.json();
    result.textContent = "Login successful!";
    window.location = body.redirect || "/";

  } catch (err) {
    result.textContent = err.message || "WebAuthn login failed.";
    console.error("WebAuthn error:", err);
  } finally {
    if (btn && btn.tagName === "BUTTON") btn.disabled = false;
  }
}

// Polyfill for b64url <-> Uint8Array, only for legacy browsers
function b64urlToBuf(b64) {
  b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function bufToB64url(buf) {
  let str = '';
  new Uint8Array(buf).forEach(b => str += String.fromCharCode(b));
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

