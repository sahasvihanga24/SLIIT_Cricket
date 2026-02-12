const bcrypt = require("bcryptjs");
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
    const { phone } = JSON.parse(event.body || "{}");
    if (!phone) return { statusCode: 400, headers, body: JSON.stringify({ error: "phone is required" }) };

    const playerRes = await query("SELECT id, status FROM players WHERE phone=$1 LIMIT 1", [phone]);
    if (playerRes.rowCount === 0) return { statusCode: 404, headers, body: JSON.stringify({ error: "Phone not registered" }) };

    const otp = String(Math.floor(100000 + Math.random() * 900000));
    const otpHash = await bcrypt.hash(otp, 10);
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await query(
      `INSERT INTO otp_codes (phone, otp_hash, expires_at, attempts, used)
       VALUES ($1,$2,$3,0,false)`,
      [phone, otpHash, expiresAt]
    );

    // Free mode: show OTP in response
    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, otp }) };
  } catch (e) {
    return { statusCode: 500, headers, body: JSON.stringify({ error: e.message }) };
  }
};
