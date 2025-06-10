<!-- SPDX-License-Identifier: Apache-2.0 -->

# Auth-Lib-Provider-Keycloak

## Overview

A provider to be used to bridge Tazama Authentication with a keycloak backend. This provider is reliant on the [auth-lib](https://github.com/tazama-lf/auth-lib) package to function.

## Installation

A personal access token is required to install this repository. For more information read the following.
https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages#about-scopes-and-permissions-for-package-registries

Make sure you've got an .npmrc file in the root of your project, specifying where the @tazama-lf repo is. 
```
@tazama-lf:registry=https://npm.pkg.github.com
```

Thereafter you can run 
  > npm install @tazama-lf/auth-lib 
  > npm install @tazama-lf/auth-lib-provider-keycloak 

## Usage

Ensure whichever application consumes this provider alongside auth-lib set the environmental variables unique to this provider as defined below

##### Environment variables

| Variable | Purpose | Example
| ------ | ------ | ------ |
| `AUTH_URL` | Base URL where KeyCloak is hosted | `https://keycloak.example.com:8080`
| `KEYCLOAK_REALM` | KeyCloak Realm for Tazama | `tazama`
| `CLIENT_ID` | KeyCloak defined client for auth-lib | `auth-lib-client`
| `CLIENT_SECRET` | The secret of the KeyCloak client | `someClientGeneratedSecret123`
