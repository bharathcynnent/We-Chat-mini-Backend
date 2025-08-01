// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
require('dotenv').config();

const app = express();
const port = 3000;

const appId = process.env.WECHAT_APP_ID;
const appSecret = process.env.WECHAT_APP_SECRET;

app.use(cors());
app.use(bodyParser.json());

app.post('/getOpenId', async (req, res) => {
  const { code } = req.body;

  if (!code) {
    return res.status(400).json({ error: 'Missing code' });
  }

  try {
    const wechatResponse = await axios.get('https://api.weixin.qq.com/sns/jscode2session', {
      params: {
        appid: appId,
        secret: appSecret,
        js_code: code,
        grant_type: 'authorization_code',
      }
    });

    res.json(wechatResponse.data); // openid, session_key, etc.
  } catch (error) {
    console.error('Error fetching openid:', error.message);
    res.status(500).json({ error: 'Failed to fetch openid' });
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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
