# SPDX-License-Identifier: Apache-2.0
ARG BUILD_IMAGE=node:20-bullseye
ARG RUN_IMAGE=gcr.io/distroless/nodejs20-debian11:nonroot

FROM ${BUILD_IMAGE} AS builder
LABEL stage=build
# TS -> JS stage

WORKDIR /home/app
COPY ./src ./src
COPY ./package*.json ./
COPY ./tsconfig.json ./
COPY .npmrc ./
ARG GH_TOKEN

RUN npm ci --ignore-scripts
RUN npm run build

FROM ${BUILD_IMAGE} AS dep-resolver
LABEL stage=pre-prod
# To filter out dev dependencies from final build

COPY package*.json ./
COPY .npmrc ./
ARG GH_TOKEN
RUN npm ci --omit=dev --ignore-scripts

FROM ${RUN_IMAGE} AS run-env
USER nonroot

WORKDIR /home/app
COPY --from=dep-resolver /node_modules ./node_modules
COPY --from=builder /home/app/build ./build
COPY package.json ./
COPY deployment.yaml ./
COPY service.yaml ./

# Turn down the verbosity to default level.
ENV NPM_CONFIG_LOGLEVEL=warn

ENV FUNCTION_NAME=auth-service
ENV NODE_ENV=production
ENV MAX_CPU=

# Fastify
ENV PORT=3000
ENV HOST=0.0.0.0

# Auth Lib
ENV AUTH_PROVIDER=@tazama-lf/auth-lib-provider-keycloak
ENV CERT_PATH_PRIVATE=private_key.pem

# Provider: @tazama-lf/auth-lib-provider-keycloak
ENV AUTH_URL=http://localhost:8080
ENV KEYCLOAK_REALM=tazama
ENV CLIENT_SECRET=
ENV CLIENT_ID=

EXPOSE 3000

# Execute watchdog command
CMD ["build/index.js"]
