/*
 * Netlify function behind the Zoom session page.
 *
 * It answers two addresses:
 *   GET  /api/session  ->  page title and whether setup is complete (no secrets)
 *   POST /api/join     ->  a fresh Zoom signature plus the meeting number and passcode
 *
 * The signature is made with your Zoom Client Secret, which is why it is
 * created here on Netlify's servers and never inside the page.
 *
 * Settings are read from Netlify environment variables
 * (Project configuration > Environment variables):
 *
 *   ZOOM_CLIENT_ID       required
 *   ZOOM_CLIENT_SECRET   required
 *   MEETING_NUMBER       required  (spaces are fine)
 *   MEETING_PASSCODE     optional
 *   PAGE_TITLE           optional  (default: Live session)
 *   ASK_EMAIL            optional  (yes for Zoom Webinars)
 *   PLAYER_LANGUAGE      optional  (default: en-US; e.g. nl-NL)
 *
 * After changing a variable, trigger a new deploy so it takes effect.
 */

import crypto from "node:crypto";

function loadSettings() {
  const get = (name) => (process.env[name] || "").trim();
  return {
    clientId: get("ZOOM_CLIENT_ID"),
    clientSecret: get("ZOOM_CLIENT_SECRET"),
    // Zoom shows meeting IDs as "123 4567 8901"; keep the digits only.
    meetingNumber: get("MEETING_NUMBER").replace(/\D/g, ""),
    passcode: get("MEETING_PASSCODE"),
    title: get("PAGE_TITLE") || "Live session",
    askEmail: /^(yes|true|1)$/i.test(get("ASK_EMAIL")),
    // Only accept codes shaped like "nl-NL"; anything else falls back to English.
    language: /^[a-z]{2}-[A-Z]{2}$/.test(get("PLAYER_LANGUAGE")) ? get("PLAYER_LANGUAGE") : "en-US",
  };
}

function missingSettings(s) {
  const missing = [];
  if (!s.clientId) missing.push("ZOOM_CLIENT_ID");
  if (!s.clientSecret) missing.push("ZOOM_CLIENT_SECRET");
  if (!s.meetingNumber) missing.push("MEETING_NUMBER");
  return missing;
}

const base64url = (input) => Buffer.from(input).toString("base64url");

// Always role 0 (attendee) and always for the one configured meeting, so
// this can never be used to host a meeting or to get into a different one.
function createSignature(s) {
  const iat = Math.floor(Date.now() / 1000) - 30;
  const exp = iat + 60 * 60 * 2; // valid for two hours

  const header = { alg: "HS256", typ: "JWT" };
  const payload = {
    appKey: s.clientId,
    mn: s.meetingNumber,
    role: 0,
    iat,
    exp,
    tokenExp: exp,
  };

  const unsigned = base64url(JSON.stringify(header)) + "." + base64url(JSON.stringify(payload));
  const signature = crypto.createHmac("sha256", s.clientSecret).update(unsigned).digest("base64url");
  return unsigned + "." + signature;
}

const json = (status, body) =>
  new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });

export default async (req) => {
  const { pathname } = new URL(req.url);
  const s = loadSettings();
  const missing = missingSettings(s);

  if (req.method === "GET" && pathname === "/api/session") {
    return json(200, {
      title: s.title,
      askEmail: s.askEmail,
      language: s.language,
      missing,
    });
  }

  if (req.method === "POST" && pathname === "/api/join") {
    if (missing.length) {
      return json(503, { error: "Setup is not finished.", missing });
    }
    return json(200, {
      signature: createSignature(s),
      meetingNumber: s.meetingNumber,
      passcode: s.passcode,
    });
  }

  return json(404, { error: "Not found" });
};

export const config = {
  path: ["/api/session", "/api/join"],
};
