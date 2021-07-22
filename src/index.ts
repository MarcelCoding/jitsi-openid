import * as express from 'express';
import {sign as jwtSign} from 'jsonwebtoken';
import {auth as openIdAuth} from 'express-openid-connect';

const JITSI = 'jitsi';

const PORT = process.env.PORT ?? 3000;
const {JITSI_SECRET, JITSI_URL, JITSI_SUB} = process.env;

if (!JITSI_SECRET || !JITSI_URL || !JITSI_SUB) {
  console.error(`Missing environment variable JITSI_SECRET, JITSI_URL or JITSI_SUB.`);
  process.exit(1);
}

const app = express();

app.use(openIdAuth());

function sign(name: string, email: string, id: string, allowedRoom: string): string {
  return jwtSign({
    context: {
      user: {name, email, id}
    },
    aud: JITSI,
    iss: JITSI,
    sub: JITSI_SUB,
    room: allowedRoom
  }, JITSI_SECRET!);
}

app.get('/room/:room', (req, res) => {
  if (!req.oidc.user) {
    throw new Error('Missing user information.');
  }

  const {sub, name, email} = req.oidc.user;
  const token = sign(name, email, sub, "*");

  const params = new URLSearchParams();
  params.set('jwt', token);

  res.redirect(`${JITSI_URL}/${req.params.room}?${params.toString()}`);
});

app.listen(PORT, () => console.log(`Http Server is listening on port ${PORT}.`));
