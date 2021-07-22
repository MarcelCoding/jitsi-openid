ARG NODE_VERSION=14

FROM node:${NODE_VERSION}-alpine AS builder

WORKDIR /src

COPY package*.json .
RUN npm ci --no-audit

COPY webpack.config.js .
COPY tsconfig.json .
COPY src ./src/

RUN npm run build

FROM node:${NODE_VERSION}-alpine

ENV PORT=3000
ENV NODE_ENV=production

WORKDIR /app

COPY --from=builder /src/dist/index.js* .
COPY LICENSE .

EXPOSE ${PORT}

ENTRYPOINT ["node", "index.js"]
