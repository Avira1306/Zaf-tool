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
    const clientEmail = context.env.GOOGLE_CLIENT_EMAIL;
    const privateKey = context.env.GOOGLE_PRIVATE_KEY.replace(/\\n/g, '\n');

    // Create JWT for Google
    const jwtHeader = {
      alg: "RS256",
      typ: "JWT"
    };

    const now = Math.floor(Date.now() / 1000);

    const jwtClaim = {
      iss: clientEmail,
      scope: "https://www.googleapis.com/auth/spreadsheets",
      aud: "https://oauth2.googleapis.com/token",
      exp: now + 3600,
      iat: now
    };

    const encoder = new TextEncoder();

    const base64UrlEncode = (obj) =>
      btoa(JSON.stringify(obj))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");

    const headerEncoded = base64UrlEncode(jwtHeader);
    const claimEncoded = base64UrlEncode(jwtClaim);

    const unsignedToken = `${headerEncoded}.${claimEncoded}`;

    const keyData = await crypto.subtle.importKey(
      "pkcs8",
      str2ab(privateKey),
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
      unsignedToken +
      "." +
      arrayBufferToBase64Url(signature);

    // Exchange JWT for access token
    const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${signedToken}`
    });

    const tokenData = await tokenResponse.json();
    const accessToken = tokenData.access_token;

    // Append row to sheet
    await fetch(
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

    return Response.redirect(
      `${new URL(context.request.url).origin}?success=true`,
      302
    );

  } catch (error) {
    return new Response("Error submitting form", { status: 500 });
  }
}

function str2ab(str) {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0; i < str.length; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
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
