FROM node:14.16.0-alpine AS builder
WORKDIR /opt

COPY ./index.js ./index.js
# COPY ../../package.json ./package.json
# COPY ../../package-lock.json ./package-lock.json

RUN npm install express

CMD ["node", "./index.js"]
