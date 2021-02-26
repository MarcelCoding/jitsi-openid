FROM node:15-alpine3.12
ENV PORT=3000

WORKDIR /app

COPY package*.json .
RUN npm ci

COPY src/ src/
COPY LICENSE .

EXPOSE ${PORT}

ENTRYPOINT [ "npm", "run", "start" ]
