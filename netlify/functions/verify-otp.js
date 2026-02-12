const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { query } = require("./_db");

const headers = {
  "Content-Type": "application/json",
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Allow-Methods": "POST, OPTIONS"
};

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") return { statusCode: 204, headers, body: "" };
  if (event.httpMethod !== "POST") return { statusCode: 405, headers, body: JSON.stringify({ error: "Use POST" }) };

  try {
    const { phone, otp } = JSON.parse(event.body || "{}");
    if (!phone || !otp) return { statusCode: 400, headers, body: JSON.stringify({ error: "phone and otp required" }) };
    if (!process.env.JWT_SECRET) return { statusCode: 500, headers, body: JSON.stringify({ error: "JWT_SECRET missing" }) };

    const otpRes = await query(
      `SELECT id, otp_hash, expires_at, attempts, used
       FROM otp_codes
       WHERE phone=$1
       ORDER BY created_at DESC
       LIMIT 1`,
      [phone]
    );
    if (otpRes.rowCount === 0) return { statusCode: 400, headers, body: JSON.stringify({ error: "No OTP requested" }) };

    const row = otpRes.rows[0];
    if (row.used) return { statusCode: 400, headers, body: JSON.stringify({ error: "OTP already used" }) };
    if (new Date(row.expires_at) < new Date()) return { statusCode: 400, headers, body: JSON.stringify({ error: "OTP expired" }) };
    if (row.attempts >= 5) return { statusCode: 429, headers, body: JSON.stringify({ error: "Too many attempts" }) };

    const ok = await bcrypt.compare(String(otp), row.otp_hash);
    if (!ok) {
      await query("UPDATE otp_codes SET attempts = attempts + 1 WHERE id=$1", [row.id]);
      return { statusCode: 401, headers, body: JSON.stringify({ error: "Invalid OTP" }) };
    }

    await query("UPDATE otp_codes SET used = true WHERE id=$1", [row.id]);

    const playerRes = await query("SELECT id, full_name, phone, role FROM players WHERE phone=$1 LIMIT 1", [phone]);
    const player = playerRes.rows[0];

    const token = jwt.sign(
      { player_id: player.id, role: player.role, phone: player.phone },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, token, player }) };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
  }
};
