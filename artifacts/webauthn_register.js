// webauthn_register.js

// Polyfill used only for legacy browsers lacking parseCreationOptionsFromJSON
function b64urlToBuf(b64) {
  b64 = b64.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}
function bufToB64url(buf) {
  let str = "";
  new Uint8Array(buf).forEach(b => str += String.fromCharCode(b));
  return btoa(str).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
}

/**
 * Main entry for WebAuthn passkey registration
 * @param {string} buttonId - Button to disable for duration (optional, improves UX)
 * @param {string} resultDivId - Element to display status message in.
 */
async function startWebAuthnRegistration(buttonId, resultDivId) {
  const nameEl = document.getElementById("passkey-name");
  const result = document.getElementById(resultDivId);
  const label = nameEl.value.trim();
  const usernameEl = document.getElementById("register-username");
  let username = usernameEl ? usernameEl.value.trim() : "";
  let btn = document.getElementById(buttonId);

  // 1) Feature-detect
  if (!window.PublicKeyCredential || !navigator.credentials) {
    result.textContent = "This browser does not support WebAuthn.";
    return;
  }
  if (!label) {
    nameEl.classList.add("is-invalid");
    result.textContent = "Please enter a device label before registering.";
    nameEl.focus();
    return;
  }
  nameEl.classList.remove("is-invalid");
  result.textContent = "";

  // 2) Fetch registration options
  btn && (btn.disabled = true);
  try {
    // **Send username to backend if present**
    let url = "/webauthn/options/register";
    if (username) url += "?username=" + encodeURIComponent(username);
    let opts = await fetch(url).then(r => {
      if (!r.ok) throw new Error("Failed to fetch passkey options.");
      return r.json();
    });

    // **Always use the username returned by the backend!**
    username = opts.username;

    // 3) Use built-in WebAuthn option parser if available
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
      opts = PublicKeyCredential.parseCreationOptionsFromJSON(opts);
    } else {
      // Fallback: manual array buffer decoding per b64url
      opts.challenge = b64urlToBuf(opts.challenge);
      opts.user.id   = b64urlToBuf(opts.user.id);
      if (Array.isArray(opts.excludeCredentials)) {
        opts.excludeCredentials = opts.excludeCredentials.map(c => ({
          ...c, id: b64urlToBuf(c.id)
        }));
      }
    }

    // 4) Call WebAuthn API
    result.textContent = "Follow browser prompt for passkey registration…";
    const cred = await navigator.credentials.create({ publicKey: opts });
    if (!cred) throw new Error("No credential returned.");

    // 5) Build submitted payload — prefer .toJSON() shape
    const payload = typeof cred.toJSON === "function"
      ? { ...cred.toJSON(), name: label, username }
      : {
          id: cred.id,
          rawId: bufToB64url(cred.rawId),
          type: cred.type,
          response: {
            attestationObject: bufToB64url(cred.response.attestationObject),
            clientDataJSON:    bufToB64url(cred.response.clientDataJSON)
          },
          name: label,
          username: username
        };

    const csrf =
      document.querySelector('meta[name="csrf-token"]')?.content ?? "";

    // 6) POST credential to server
    const resp = await fetch("/webauthn/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf
      },
      body: JSON.stringify(payload)
    });

    // 7) Handle server-side result
    if (!resp.ok) {
      let msg = "Registration failed.";
      try {
        msg = (await resp.json()).error || msg;
      } catch {}
      result.textContent = msg;
      return;
    }
    const body = await resp.json();
    // Show assigned username clearly if needed
    if (body.username) {
      result.textContent = "Passkey registered! Username: " + body.username;
    } else {
      result.textContent = "Passkey registered!";
    }
    if (body.redirect) window.location = body.redirect;

  } catch (err) {
    result.textContent = err.message || "Registration failed.";
    console.error("WebAuthn register error:", err);
  } finally {
    btn && (btn.disabled = false);
  }
}