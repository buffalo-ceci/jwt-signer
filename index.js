import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';

const app = express();
app.use(bodyParser.json());

app.post('/generate-jwt', (req, res) => {
  const serviceAccount = req.body;

  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;

  const header = {
    alg: "RS256",
    typ: "JWT"
  };

  const payload = {
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/cloud-platform",
    aud: serviceAccount.token_uri,
    iat,
    exp
  };

  const base64url = (obj) =>
    Buffer.from(JSON.stringify(obj))
      .toString("base64")
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

  const encodedHeader = base64url(header);
  const encodedPayload = base64url(payload);
  const dataToSign = `${encodedHeader}.${encodedPayload}`;

  const signer = crypto.createSign('RSA-SHA256');
  signer.update(dataToSign);
  const signature = signer.sign(serviceAccount.private_key, 'base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  const jwt = `${dataToSign}.${signature}`;
  res.json({ jwt });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ JWT Signer running on http://localhost:${PORT}`);
});
