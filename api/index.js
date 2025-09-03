import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import serverless from 'serverless-http';
import {
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';

const app = express();
app.use(cors());
app.use(bodyParser.json());

const rpName = 'WebAuthn Demo';
// ✅ Use env vars (fallback to localhost for dev)
const rpID = process.env.RP_ID || 'localhost';
const origin = process.env.ORIGIN || 'http://localhost:5173';

const users = new Map(); // In-memory (replace with DB in production)

app.post('/register/options', async (req, res) => {
  const { username } = req.body;
  if (!username) return res.status(400).send('Username required');

  const userId = isoUint8Array.fromUTF8String(username);

  const options = await generateRegistrationOptions({
    rpName,
    rpID,
    userID: userId,
    userName: username,
    attestationType: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'preferred',
    },
  });

  users.set(username, {
    id: userId,
    username,
    currentChallenge: options.challenge,
  });

  res.json(options);
});

app.post('/register/verify', async (req, res) => {
  const { username, attResp } = req.body;
  const user = users.get(username);

  try {
    const verification = await verifyRegistrationResponse({
      response: attResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (verification.verified) {
      user.credential = verification.registrationInfo;
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

app.post('/login/options', async (req, res) => {
  const { username } = req.body;
  const user = users.get(username);

  if (!user?.credential) return res.status(400).send('User not registered');

  const allowCredentials = [
    {
      id: user.credential.credentialID,
      type: 'public-key',
      transports: user.credential.transports ?? ['internal'],
    },
  ];

  const options = await generateAuthenticationOptions({
    rpID,
    allowCredentials,
    userVerification: 'preferred',
  });

  user.currentChallenge = options.challenge;

  res.json(options);
});

app.post('/login/verify', async (req, res) => {
  const { username, authResp } = req.body;
  const user = users.get(username);

  try {
    const verification = await verifyAuthenticationResponse({
      response: authResp,
      expectedChallenge: user.currentChallenge,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialPublicKey: user.credential.credentialPublicKey,
        credentialID: user.credential.credentialID,
        counter: user.credential.counter,
      },
    });

    if (verification.verified) {
      user.credential.counter = verification.authenticationInfo.newCounter;
    }

    res.json({ verified: verification.verified });
  } catch (err) {
    console.error(err);
    res.status(400).json({ verified: false, error: err.message });
  }
});

export default serverless(app);
