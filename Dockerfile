FROM node:24.15.0-bookworm-slim

RUN  apt-get update &&  apt-get install --assume-yes --no-install-recommends dumb-init && \
apt-get autoremove --assume-yes &&  apt-get clean && rm --recursive --force /var/lib/apt/lists/*

WORKDIR /usr/src/app
COPY . /usr/src/app

ENV NODE_ENV=production
RUN npm ci --only=production

CMD ["dumb-init", "node", "main.js"]
