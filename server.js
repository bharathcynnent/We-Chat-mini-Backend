// server.js
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();

const APPID  = process.env.WECHAT_APP_ID;
const SECRET  = process.env.WECHAT_APP_SECRET;

app.use(cors());
app.use(bodyParser.json());


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

app.post('/wechat-login', async (req, res) => {
  const { code, encryptedData, iv } = req.body;

  if (!code || !encryptedData || !iv) {
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
    const decryptedUserInfo = decryptData(sessionKey, encryptedData, iv);

    if (!decryptedUserInfo) {
      return res.status(500).json({ error: 'Failed to decrypt data' });
    }

    res.json(decryptedUserInfo);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/info', (req, res) => {
  res.json({
    message: 'Welcome to the WeChat Mini Program!',
    app: 'wechat mini',
    contact: '9352355',
    services: ['message Service', 'calls']
  });
});

app.listen(3000, () => {
  console.log('Server running on http://localhost:3000');
});