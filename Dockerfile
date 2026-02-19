FROM node:22-alpine

WORKDIR /app

COPY package.json yarn.lock* ./
RUN yarn install --production --frozen-lockfile 2>/dev/null || yarn install --production

COPY src/ ./src/

CMD ["yarn", "start"]
