```javascript
export async function onRequestPost(context) {
  try {

    const formData = await context.request.formData();
    const url = new URL(context.request.url);

    // -------- READ FORM DATA --------
    const formType  = formData.get("form_type") || "team_quote";
    const name      = formData.get("name")      || "";
    const email     = formData.get("email")     || "";
    const role      = formData.get("role")      || "";
    const phone     = formData.get("phone")     || "";
    const industry  = formData.get("industry")  || "";
    const teamSize  = formData.get("team_size") || "";
    const company   = formData.get("company")   || "";
    const message   = formData.get("message")   || "";

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

   const unsignedToken = `${headerEncoded}.${claimEncoded}`;

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
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${signedToken}`
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
      role,
      phone,
      industry,
      teamSize,
      company,
      message
    ];

    await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1:append?valueInputOption=USER_ENTERED`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${tokenData.access_token}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ values: [row] })
      }
    );

    // -------- SEND DOWNLOAD EMAIL --------
    if (formType === "trial" || formType === "lite_download") {

      const downloadLink = "https://zaftool.com/download.html";

      await fetch("https://api.resend.com/emails", {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${context.env.RESEND_API_KEY}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          from: "ZAF Tool <download@zaftool.com>",
          to: email,
          subject: "Your ZAF Tool Download",
          html: `
            <h2>Your download is ready</h2>

            <p>Hi ${name || "there"},</p>

            <p>Thanks for trying <strong>ZAF Tool</strong>.</p>

            <p>Click the button below to download your Excel add-in.</p>

            <p>
              <a href="${downloadLink}" 
              style="background:#2563EB;color:white;padding:12px 20px;border-radius:6px;text-decoration:none;">
              Download ZAF Tool
              </a>
            </p>

            <p style="margin-top:20px;font-size:13px;color:#666;">
              Role: ${role || "Not specified"}
            </p>
          `
        })
      });

    }

    // -------- REDIRECT USER --------
    const redirectParam = url.searchParams.get("redirect");

    let redirectTo;

    if (redirectParam) {
      redirectTo = `${url.origin}${redirectParam}`;
    }
    else if (formType === "trial" || formType === "lite_download") {
      redirectTo = `${url.origin}/email-sent.html`;
    }
    else {
      redirectTo = `${url.origin}/?success=true`;
    }

    return Response.redirect(redirectTo, 302);

  } catch (error) {

    return new Response("ERROR: " + error.message, {
      status: 500
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
```
