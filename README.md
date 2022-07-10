# Jitsi OpenID

Jitsi OpenID is an authentication adapter to provide [jitsi](https://jitsi.org/) the ability to use single sign on
via [OpenID Connect](https://openid.net/connect/).

## Deployment

**This guide is based of the [docker setup from jitsi](https://github.com/jitsi/docker-jitsi-meet/).**

This image is available in [Docker Hub](https://hub.docker.com/r/marcelcoding/jitsi-openid) and the
[GitHub Container Registry](https://github.com/users/MarcelCoding/packages/container/package/jitsi-openid):

```
marcelcoding/jitsi-openid:latest
ghcr.io/marcelcoding/jitsi-openid:latest
```

### Docker "run" Command

```bash
docker run \
  -p 3000:3000 \
  -e JITSI_SECRET=SECURE_SECRET \
  -e JITSI_URL=https://meet.example.com \
  -e JITSI_SUB=meet.example.com \
  -e ISSUER_URL=https://id.example.com \
  -e BASE_URL=https://auth.meet.example.com \
  -e CLIENT_ID=meet.example.com \
  -e CLIENT_SECRET=SECURE_SECRET \
  --rm \
  marcelcoding/jitsi-openid:latest
```

### Docker Compose

````yaml
# docker-compose.yaml
version: '3.8'

services:

  jitsi-openid:
    image: marcelcoding/jitsi-openid:latest
    restart: always
    environment:
      - 'JITSI_SECRET=SECURE_SECRET'             # <- shared with jitsi (JWT_APP_SECRET -> see .env from jitsi),
                                                 #    secret to sign jwt tokens
      - 'JITSI_URL=https://meet.example.com'     # <- external url of jitsi
      - 'JITSI_SUB=meet.example.com'             # <- shared with jitsi (JWT_APP_ID -> see .env from jitsi),
                                                 #    id of jitsi
      - 'ISSUER_URL=https://id.example.com'      # <- base URL of your OpenID Connect provider
                                                 #    Keycloak: https://id.example.com/auth/realms/<realm>
      - 'BASE_URL=https://auth.meet.example.com' # <- base URL of this application
      - 'CLIENT_ID=meet.example.com'             # <- OpenID Connect Client ID
      - 'CLIENT_SECRET=SECURE_SECRET'            # <- OpenID Connect Client secret
    # - 'ACR_VALUES=password email'              # <- OpenID Context Authentication Context Requirements,
                                                 #    space seperated list of allowed actions (OPTIONAL), see
                                                 #    https://github.com/MarcelCoding/jitsi-openid/issues/122
    ports:
      - '3000:3000'
````

To generate the `JITSI_SECRET` you can use one of the following command:
```bash
cat /dev/urandom | tr -dc a-zA-Z0-9 | head -c128; echo
```

### Jitsi Configuration

If you have problems understating this have a look here: https://github.com/MarcelCoding/jitsi-openid/issues/80

````bash
# https://github.com/jitsi/docker-jitsi-meet/blob/master/env.example
ENABLE_AUTH=1
#ENABLE_GUESTS=1
AUTH_TYPE=jwt
JWT_APP_ID=meet.example.com # see JITSI_ID
JWT_APP_SECRET=SECRET # see JITSI_SECRET
JWT_ACCEPTED_ISSUERS=jitsi
JWT_ACCEPTED_AUDIENCES=jitsi
TOKEN_AUTH_URL=https://auth.meet.example.com/room/{room}
````

### Jitsi JWTs

The JWTs are populated using the data returned by your IDP.
This includes the user id, email and name.

The `sub` extracted from the `prefered_username` field, if that isn't preset the `sub` field is used.

The `name` is extracted from the `name` field, if that isn't preset a concatenation of `given_name`, `middle_name` and `family_name` is used. If all tree of them are also not present the `prefered_username` is used.

Translations are not respected: https://github.com/MarcelCoding/jitsi-openid/issues/117#issuecomment-1172406703

The `affiliation` is straight up passed, without any modifications or alternatives. It can be used to restrict the permissions a user has in a specific room in jitsi. See https://github.com/jitsi-contrib/prosody-plugins/tree/main/token_affiliation for more information.

## License

[LICENSE](LICENSE)
