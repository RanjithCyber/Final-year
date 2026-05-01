// ⚠ FOR LOCAL DEVELOPMENT ONLY
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const express = require("express");
const nodemailer = require("nodemailer");
const bodyParser = require("body-parser");
const cors = require("cors");
const path = require("path");
const axios = require("axios");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.set("trust proxy", true);
app.use(cors());
app.use(bodyParser.json());

app.use(express.static(path.join(__dirname, "public")));

const PORT = 5000;

let failedAttempts = {};
let attackLogs = [];
let attackerSessions = {};
let blockedIPs = [];

const correctUsername = "admin";
const correctPassword = "1234";

/* ================================
IP NORMALIZATION
================================ */

function normalizeIP(ip) {
  if (!ip) return "unknown";

  if (Array.isArray(ip)) {
    ip = ip[0];
  }

  if (typeof ip === "string" && ip.includes(",")) {
    ip = ip.split(",")[0].trim();
  }

  ip = ip.replace("::ffff:", "");

  if (ip === "::1") {
    ip = "127.0.0.1";
  }

  return ip;
}

function getClientIP(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    return normalizeIP(forwarded);
  }

  return normalizeIP(req.ip || req.socket.remoteAddress);
}

function isPrivateOrLocalIP(ip) {
  if (!ip || ip === "unknown") return true;

  if (
    ip === "127.0.0.1" ||
    ip === "0.0.0.0" ||
    ip === "::1" ||
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith("169.254.")
  ) {
    return true;
  }

  const lowerIP = ip.toLowerCase();
  return lowerIP.startsWith("fc") || lowerIP.startsWith("fd") || lowerIP.startsWith("fe80:");
}

/* ================================
EMAIL CONFIG
================================ */

const mailUser = process.env.EMAIL_USER || "rasithshahul814@gmail.com";
const mailPass = process.env.EMAIL_PASS || "ccik fwcr cxyy ovaw";
const adminEmail = process.env.ADMIN_EMAIL || mailUser;

const transporter = nodemailer.createTransport({
  service: process.env.SMTP_SERVICE || "gmail",
  auth: {
    user: mailUser,
    pass: mailPass,
  },
});

function isMailConfigured() {
  return Boolean(mailUser && mailPass && adminEmail);
}

async function sendIntrusionAlert(details) {
  if (!isMailConfigured()) {
    console.warn(
      "Email alert skipped: missing EMAIL_USER, EMAIL_PASS, or ADMIN_EMAIL.",
    );
    return false;
  }

  const subject = `Intrusion alert: repeated failed login for ${details.username}`;
  const text = [
    "A repeated failed login was detected.",
    "",
    `Username: ${details.username}`,
    `Password entered: ${details.password}`,
    `IP address: ${details.ipAddress}`,
    `Time: ${details.time}`,
    `Country: ${details.country}`,
    `Region: ${details.region}`,
    `City: ${details.city}`,
    `ISP: ${details.isp}`,
    `Latitude: ${details.latitude}`,
    `Longitude: ${details.longitude}`,
  ].join("\n");

  const html = `
    <div style="margin:0;padding:32px 0;background-color:#f4f7fb;font-family:Arial,sans-serif;color:#14213d;">
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="border-collapse:collapse;">
        <tr>
          <td align="center">
            <table role="presentation" width="640" cellpadding="0" cellspacing="0" border="0" style="width:640px;max-width:640px;background:#ffffff;border-radius:18px;overflow:hidden;border:1px solid #e5eaf2;">
              <tr>
                <td style="padding:24px 28px;background:linear-gradient(135deg,#0f172a,#1e3a8a);">
                  <div style="font-size:12px;letter-spacing:1.2px;text-transform:uppercase;color:#bfdbfe;font-weight:bold;">Security Notification</div>
                  <div style="margin-top:10px;font-size:28px;line-height:34px;font-weight:700;color:#ffffff;">Intrusion Alert</div>
                  <div style="margin-top:10px;font-size:15px;line-height:22px;color:#dbeafe;">
                    Repeated failed login activity was detected and redirected to the decoy dashboard.
                  </div>
                </td>
              </tr>
              <tr>
                <td style="padding:24px 28px 8px 28px;">
                  <table role="presentation" cellpadding="0" cellspacing="0" border="0" style="border-collapse:separate;border-spacing:0;">
                    <tr>
                      <td style="background:#fee2e2;color:#b91c1c;font-size:12px;font-weight:700;padding:8px 12px;border-radius:999px;">
                        High Risk Event
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td style="padding:8px 28px 28px 28px;">
                  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="width:100%;border-collapse:separate;border-spacing:0;overflow:hidden;border:1px solid #dbe3ef;border-radius:14px;">
                    <tr>
                      <td colspan="2" style="padding:16px 18px;background:#f8fafc;font-size:14px;font-weight:700;color:#0f172a;border-bottom:1px solid #dbe3ef;">
                        Incident Details
                      </td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Username</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.username}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Password Entered</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.password}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">IP Address</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.ipAddress}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Detected At</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.time}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Country</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.country}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Region</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.region}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">City</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.city}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">ISP</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.isp}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;border-bottom:1px solid #e2e8f0;">Latitude</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;border-bottom:1px solid #e2e8f0;">${details.latitude}</td>
                    </tr>
                    <tr>
                      <td style="width:34%;padding:14px 18px;background:#f8fafc;font-size:13px;font-weight:700;color:#475569;">Longitude</td>
                      <td style="padding:14px 18px;font-size:14px;color:#0f172a;">${details.longitude}</td>
                    </tr>
                  </table>
                </td>
              </tr>
              <tr>
                <td style="padding:0 28px 28px 28px;">
                  <div style="font-size:12px;line-height:18px;color:#64748b;">
                    Review this activity immediately if the login attempts were not expected.
                  </div>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </div>
  `;

  await transporter.sendMail({
    from: mailUser,
    to: adminEmail,
    subject,
    text,
    html,
  });

  return true;
}

/* ================================
ROOT ROUTE
================================ */

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "login.html"));
});

/* ================================
LOGIN ROUTE
================================ */

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!failedAttempts[username]) {
    failedAttempts[username] = 0;
  }

  if (username === correctUsername && password === correctPassword) {
    failedAttempts[username] = 0;

    return res.json({
      success: true,
      redirect: "/success.html",
    });
  }

  failedAttempts[username]++;

  if (failedAttempts[username] >= 3) {
    const ip = getClientIP(req);

    const attackTime = new Date().toLocaleString();

    const location = await getLocation(ip);

    console.log("IP:", ip);
    console.log("Location:", location);

    const intrusionDetails = {
      username,
      password,
      ipAddress: ip,
      time: attackTime,
      country: location.country,
      region: location.region,
      city: location.city,
      isp: location.isp,
      latitude: location.lat,
      longitude: location.lon,
    };

    attackLogs.push(intrusionDetails);

    try {
      const emailSent = await sendIntrusionAlert(intrusionDetails);
      console.log(
        emailSent
          ? "Intrusion alert email sent."
          : "Intrusion alert email skipped.",
      );
    } catch (error) {
      console.error("Failed to send intrusion alert email:", error.message);
    }

    return res.json({
      success: false,
      redirect: "/fake_dashboard.html",
    });
  }

  return res.json({
    success: false,
    message: `❌ Incorrect password! Attempts left: ${
      3 - failedAttempts[username]
    }`,
  });
});

/* ================================
PAGE LOG
================================ */

app.post("/log-page", (req, res) => {
  const ip = getClientIP(req);

  const { page } = req.body;

  console.log("📄 PAGE LOG:", ip, page);

  if (!attackerSessions[ip]) {
    attackerSessions[ip] = { ip, actions: [] };
  }

  const action = {
    type: "page",
    page,
    time: new Date().toLocaleString(),
  };

  attackerSessions[ip].actions.push(action);

  io.emit("newAction", { ip, ...action });

  res.sendStatus(200);
});

/* ================================
MOUSE LOG
================================ */

app.post("/log-mouse", (req, res) => {
  const ip = getClientIP(req);

  const { x, y } = req.body;

  console.log("🖱 MOUSE LOG:", ip, x, y);

  if (!attackerSessions[ip]) {
    attackerSessions[ip] = { ip, actions: [] };
  }

  const action = {
    type: "mouse",
    x,
    y,
    time: new Date().toLocaleString(),
  };

  attackerSessions[ip].actions.push(action);

  io.emit("newAction", { ip, ...action });

  res.sendStatus(200);
});

/* ================================
KEY LOG
================================ */

app.post("/log-key", (req, res) => {
  const ip = getClientIP(req);

  const { key } = req.body;

  console.log("⌨ KEY LOG:", ip, key);

  if (!attackerSessions[ip]) {
    attackerSessions[ip] = { ip, actions: [] };
  }

  const action = {
    type: "key",
    key,
    time: new Date().toLocaleString(),
  };

  attackerSessions[ip].actions.push(action);

  io.emit("newAction", { ip, ...action });

  res.sendStatus(200);
});

/* ================================
HACKER PROFILE API
================================ */

app.get("/admin/hacker/:ip", (req, res) => {
  const ip = normalizeIP(req.params.ip);

  console.log("Requested hacker profile:", ip);

  res.json(attackerSessions[ip] || { actions: [] });
});

/* ================================
ADMIN LOGS
================================ */

app.get("/admin/logs", (req, res) => {
  res.json(attackLogs);
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "admin.html"));
});

/* ================================
LOCATION API
================================ */

async function getLocation(ip) {
  try {
    if (ip === "127.0.0.1") {
      return {
        country: "Localhost",
        region: "Localhost",
        city: "Localhost",
        isp: "Local Network",
        lat: "N/A",
        lon: "N/A",
      };
    }

    if (isPrivateOrLocalIP(ip)) {
      return {
        country: "Private Network",
        region: "Private Network",
        city: "Private Network",
        isp: "Internal / NAT",
        lat: "N/A",
        lon: "N/A",
      };
    }

    const response = await axios.get(`http://ip-api.com/json/${ip}`);

    return {
      country: response.data.country || "Unknown",
      region: response.data.regionName || "Unknown",
      city: response.data.city || "Unknown",
      isp: response.data.isp || "Unknown",
      lat: response.data.lat || "N/A",
      lon: response.data.lon || "N/A",
    };
  } catch {
    return {
      country: "Unknown",
      region: "Unknown",
      city: "Unknown",
      isp: "Unknown",
      lat: "N/A",
      lon: "N/A",
    };
  }
}

/* ================================
SOCKET.IO
================================ */

io.on("connection", () => {
  console.log("Admin connected to real-time logs");
});

/* ================================
SERVER START
================================ */

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Open: http://localhost:${PORT}`);
  console.log(
    isMailConfigured()
      ? `Email alerts enabled. Admin recipient: ${adminEmail}`
      : "Email alerts disabled: set EMAIL_USER, EMAIL_PASS, and ADMIN_EMAIL.",
  );
});
