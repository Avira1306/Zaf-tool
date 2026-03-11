export async function onRequestPost(context) {
  try {

    // -------- READ JSON BODY --------
    const body     = await context.request.json();

    const formType = body.plan  || "trial";
    const name     = body.name  || "";
    const email    = body.email || "";
    const role     = body.role  || "";

    if (!email) {
      throw new Error("Email is required");
    }

    // -------- GOOGLE SHEETS AUTH --------
    const sheetId        = context.env.SHEET_ID;
    const serviceAccount = JSON.parse(context.env.GOOGLE_SERVICE_ACCOUNT);
    const clientEmail    = serviceAccount.client_email;
    const privateKey     = serviceAccount.private_key;

    const now = Math.floor(Date.now() / 1000);

    const headerEncoded = base64UrlEncode(JSON.stringify({
      alg: "RS256",
      typ: "JWT"
    }));

    const claimEncoded = base64UrlEncode(JSON.stringify({
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/spreadsheets",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now
    }));

    const unsignedToken = headerEncoded + "." + claimEncoded;

    const encoder = new TextEncoder();

    const keyData = await crypto.subtle.importKey(
      "pkcs8",
      pemToArrayBuffer(privateKey),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      keyData,
      encoder.encode(unsignedToken)
    );

    const signedToken = unsignedToken + "." + arrayBufferToBase64Url(signature);

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=" + signedToken
    });

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("Failed to get Google access token");
    }

    // -------- WRITE TO GOOGLE SHEETS --------
    const row = [
      new Date().toISOString(),
      formType,
      name,
      email,
      role
    ];

    await fetch(
      "https://sheets.googleapis.com/v4/spreadsheets/" + sheetId + "/values/Sheet1!A1:append?valueInputOption=USER_ENTERED",
      {
        method: "POST",
        headers: {
          Authorization: "Bearer " + tokenData.access_token,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ values: [row] })
      }
    );

    // -------- SEND DOWNLOAD EMAIL --------
    const downloadLink = "https://zaftool.com/download.html";

    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + context.env.RESEND_API_KEY,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "ZAF Tool <download@zaftool.com>",
        to: email,
        subject: "Your ZAF Tool Download is Ready",
        html: `
          <div style="font-family:Arial;max-width:500px;margin:auto;padding:30px;background:#070B14;color:#fff;border-radius:10px">
            <h2 style="color:#3B82F6">Your download is ready</h2>
            <p>Hi ${name || "there"},</p>
            <p>Thanks for trying <strong>ZAF Tool</strong>. Click below to download your Excel add-in.</p>
            <p style="margin:30px 0">
              <a href="${downloadLink}"
              style="background:#2563EB;color:white;padding:14px 24px;border-radius:6px;text-decoration:none;font-weight:bold;">
              Download ZAF Tool
              </a>
            </p>
            <p style="font-size:13px;color:#888">Role: ${role || "Not specified"}</p>
            <p style="font-size:12px;color:#555">If you didn't request this, ignore this email.</p>
          </div>
        `
      })
    });

    // -------- RETURN SUCCESS --------
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });

  } catch (error) {

    return new Response(JSON.stringify({ ok: false, error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });

  }
}

// -------- HELPER FUNCTIONS --------

function pemToArrayBuffer(pem) {
  const base64 = pem
    .replace(/-----BEGIN PRIVATE KEY-----/, "")
    .replace(/-----END PRIVATE KEY-----/, "")
    .replace(/\s/g, "");

  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const view = new Uint8Array(buffer);

  for (let i = 0; i < binary.length; i++) {
    view[i] = binary.charCodeAt(i);
  }

  return buffer;
}

function base64UrlEncode(str) {
  return btoa(str)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function arrayBufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  return btoa(binary)
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}
