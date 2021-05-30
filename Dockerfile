FROM node:lts-alpine AS builder

WORKDIR /src

COPY package*.json .
RUN npm ci --no-audit

COPY . .

RUN npm run build

FROM node:lts-alpine
ENV PORT=3000

WORKDIR /app

COPY --from=builder /src/dist/index.js* .
COPY LICENSE .

EXPOSE ${PORT}

ENTRYPOINT ["node", "index.js"]
