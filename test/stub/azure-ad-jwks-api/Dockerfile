FROM node:14.16.0-alpine AS builder
WORKDIR /opt

COPY ./index.js ./index.js
COPY ./private.pem ./private.pem
# COPY ../../package.json ./package.json
# COPY ../../package-lock.json ./package-lock.json

RUN npm install express rsa-pem-to-jwk

CMD ["node", "./index.js"]
