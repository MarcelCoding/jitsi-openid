import * as express from 'express';
import {sign as jwtSign} from 'jsonwebtoken';
import {auth as openIdAuth} from 'express-openid-connect';

const PORT = process.env.PORT || 3000;

const JITSI_SECRET: string | undefined = process.env.JITSI_SECRET;
const JITSI_URL: string | undefined = process.env.JITSI_URL;
const JITSI_SUB: string | undefined = process.env.JITSI_SUB;

if (!(JITSI_SECRET && JITSI_URL && JITSI_SUB)) {
  console.error(`Missing environment variables JITSI_SECRET, JITSI_URL or JITSI_SUB.`);
  process.exit(1);
}

const app = express();

app.use(openIdAuth({
  idpLogout: true,
}));

function sign(name: string, email: string, id: string, allowedRoom: string): string {
  return jwtSign({
    "context": {
      "user": {
        "name": name,
        "email": email,
        "id": id
      }
    },
    "aud": "jitsi",
    "iss": "jitsi",
    "sub": JITSI_SUB,
    "room": allowedRoom
  }, JITSI_SECRET!);
}

app.get('/room/:room', (req, res) => {
  if (!req.oidc.user) {
    throw new Error('Missing user information.');
  }

  const {sub, name, email} = req.oidc.user;
  const token = sign(name, email, sub, "*");

  res.redirect(`${JITSI_URL}/${req.params.room}?jwt=${token}`);
});

app.listen(PORT, () => {
  console.log(`Http Server is listening on port ${PORT}.`);
});
