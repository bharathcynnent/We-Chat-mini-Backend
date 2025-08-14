// server.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const nodemailer = require("nodemailer");
const crypto = require('crypto');
require('dotenv').config();


const app = express();

const APPID = process.env.WECHAT_APP_ID;
const SECRET = process.env.WECHAT_APP_SECRET;

app.use(cors());
app.use(bodyParser.json());

const otpStore = {};

// Email transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

function decryptData(sessionKey, encryptedData, iv) {
  const _sessionKey = Buffer.from(sessionKey, 'base64');
  const _encryptedData = Buffer.from(encryptedData, 'base64');
  const _iv = Buffer.from(iv, 'base64');

  try {
    const decipher = crypto.createDecipheriv('aes-128-cbc', _sessionKey, _iv);
    decipher.setAutoPadding(true);
    let decoded = decipher.update(_encryptedData, 'binary', 'utf8');
    decoded += decipher.final('utf8');
    return JSON.parse(decoded);
  } catch (err) {
    console.error('Decryption failed:', err);
    return null;
  }
}

function verifySignature(rawData, sessionKey, signature) {
  const sha1 = crypto.createHash('sha1');
  sha1.update(rawData + sessionKey);
  const calculatedSignature = sha1.digest('hex');
  return calculatedSignature === signature;
}

app.post('/wechat-login', async (req, res) => {
  const { code, encryptedData, iv, rawData, signature } = req.body;

  if (!code || !encryptedData || !iv || !rawData || !signature) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const wxAPI = `https://api.weixin.qq.com/sns/jscode2session?appid=${APPID}&secret=${SECRET}&js_code=${code}&grant_type=authorization_code`;
    const response = await fetch(wxAPI);
    const data = await response.json();

    if (data.errcode) {
      return res.status(500).json({ error: data.errmsg });
    }

    const sessionKey = data.session_key;
    const openid = data.openid;

    const isValid = verifySignature(rawData, sessionKey, signature);
    if (!isValid) {
      return res.status(403).json({ error: 'Invalid signature. Possible fake user.' });
    }

    // Step 3: Decrypt user info
    const decryptedUserInfo = decryptData(sessionKey, encryptedData, iv);
    if (!decryptedUserInfo) {
      return res.status(500).json({ error: 'Failed to decrypt data' });
    }

    res.json({
      verified: true,
      openid,
      userInfo: decryptedUserInfo
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/register', (req, res) => {
  const { openid, email } = req.body;

  if (!openid || !email) {
    return res.status(400).json({ error: 'Missing openid or email' });
  }

  // Here you would save to a database
  // For now, just return success
  res.json({ success: true, message: `User with openid ${openid} registered with email ${email}` });
});

app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: "Email is required" });

  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 5 * 60 * 1000; // 5 minutes expiry

  otpStore[email] = { otp, expiresAt };

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Your OTP Code",
      text: `Your OTP is ${otp}. It will expire in 5 minutes.`
    });
    res.json({ message: "OTP sent successfully" });
  } catch (err) {
    console.error(err);
  res.status(500).json({ error: "Failed to send email", details: err.message });
  }
});

// 2️⃣ Verify OTP
app.post("/verify-otp", (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: "Email and OTP required" });

  const record = otpStore[email];
  if (!record) return res.status(400).json({ error: "No OTP found for this email" });

  if (Date.now() > record.expiresAt) return res.status(400).json({ error: "OTP expired" });
  if (record.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });

  delete otpStore[email]; // Clear after verification
  res.json({ message: "Email verified successfully" });
});


app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});
