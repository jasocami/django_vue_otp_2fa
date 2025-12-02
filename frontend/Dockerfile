ARG NODE_VERSION=20-bookworm
FROM node:${NODE_VERSION}

ARG NPM_LOGLEVEL=verbose

ARG NPM_URL=https://registry.npmjs.org
RUN npm set registry ${NPM_URL} && npm get registry

RUN --mount=type=cache,mode=0755,target=/root/.npm/ \
  npm install --loglevel ${NPM_LOGLEVEL} -g vite
ENV APP_HOME=/app
WORKDIR ${APP_HOME}

COPY ./package*.json ./
RUN --mount=type=cache,mode=0755,target=/root/.npm/ \
  npm install --loglevel ${NPM_LOGLEVEL}

COPY . .

ENTRYPOINT [ "npm" ]
CMD [ "run", "dev" ]
