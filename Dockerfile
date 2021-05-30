FROM node:lts-alpine
ENV PORT=3000

WORKDIR /app

COPY package*.json .
RUN npm ci --no-audit

COPY src/ src/
COPY LICENSE .

EXPOSE ${PORT}

ENTRYPOINT ["npm", "run", "start"]
