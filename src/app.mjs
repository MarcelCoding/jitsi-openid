"use strict";

import express from 'express';
import jwt from 'jsonwebtoken';
import {auth as openIdAuth} from 'express-openid-connect';

const PORT = process.env.PORT || 3000;

const JITSI_SECRET = process.env.JITSI_SECRET;
const JITSI_URL = process.env.JITSI_URL;
const JITSI_ID = process.env.JITSI_SUB;

const app = express();

app.use(openIdAuth({
  idpLogout: true,
}));

const sign = (name, email, id, allowedRoom) => {
  return jwt.sign({
    "context": {
      "user": {
        "name": name,
        "email": email,
        "id": id
      }
    },
    "aud": "jitsi",
    "iss": "jitsi",
    "sub": JITSI_ID,
    "room": allowedRoom
  }, JITSI_SECRET);
};

app.get('/:room', async (req, res) => {
  const {sub, name, email} = req.oidc.user;
  const token = sign(name, email, sub, "*");

  res.redirect(`${JITSI_URL}/${req.params.room}?jwt=${token}`);
});

app.listen(PORT, function () {
  console.log(`Http Server is listening on port ${PORT}.`);
});
