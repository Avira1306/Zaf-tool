export async function onRequestPost(context) {
  try {
    const formData = await context.request.formData();

    const name = formData.get("name") || "Team Quote Request";
    const email = formData.get("email");
    const phone = formData.get("phone");
    const industry = formData.get("industry");
    const teamSize = formData.get("team_size");
    const company = formData.get("company");
    const message = formData.get("message");

    const sheetId = context.env.SHEET_ID;

    const serviceAccount = JSON.parse(context.env.GOOGLE_SERVICE_ACCOUNT);
    const clientEmail = serviceAccount.client_email;
    const privateKey = serviceAccount.private_key;

    // ---------- JWT CREATION ----------

    const now = Math.floor(Date.now() / 1000);

    const jwtHeader = {
      alg: "RS256",
      typ: "JWT"
    };

    const jwtClaim = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/spreadsheets",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now
    };

    const encoder = new TextEncoder();

    const headerEncoded = base64UrlEncode(JSON.stringify(jwtHeader));
    const claimEncoded = base64UrlEncode(JSON.stringify(jwtClaim));

    const unsignedToken = `${headerEncoded}.${claimEncoded}`;

    // Proper PEM decoding
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

    const signedToken =
      unsignedToken + "." + arrayBufferToBase64Url(signature);

    // ---------- GET ACCESS TOKEN ----------

    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${signedToken}`
    });

    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error("Failed to get access token");
    }

    const accessToken = tokenData.access_token;

    // ---------- APPEND TO SHEET ----------

    const sheetResponse = await fetch(
      `https://sheets.googleapis.com/v4/spreadsheets/${sheetId}/values/Sheet1:append?valueInputOption=USER_ENTERED`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          values: [[
            new Date().toISOString(),
            name,
            email,
            phone,
            industry,
            teamSize,
            company,
            message
          ]]
        })
      }
    );

    if (!sheetResponse.ok) {
      throw new Error("Failed to write to Google Sheet");
    }

    return Response.redirect(
      `${new URL(context.request.url).origin}?success=true`,
      302
    );

  } catch (error) {
    return new Response("ERROR: " + error.message, { status: 500 });
  }
}

// ---------- HELPERS ----------

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
