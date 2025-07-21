'use strict';

import { type KeycloakAuthToken, type KeycloakJwtToken } from './interfaces/iKeycloakToken';

Object.defineProperty(exports, '__esModule', { value: true });
exports.KeycloakProvider = undefined;
const tslib1 = require('tslib');
const authLib1 = require('@tazama-lf/auth-lib');
const jsonwebtoken1 = tslib1.__importDefault(require('jsonwebtoken'));
const iKeycloakConfig1 = require('./interfaces/iKeycloakConfig');
class KeycloakProvider {
  realm;
  baseUrl;
  constructor() {
    if (!iKeycloakConfig1.keycloakConfig.keycloakRealm || !iKeycloakConfig1.keycloakConfig.authURL) {
      throw new Error('Missing realm or URL for Keycloak Provider');
    }
    this.realm = iKeycloakConfig1.keycloakConfig.keycloakRealm;
    this.baseUrl = iKeycloakConfig1.keycloakConfig.authURL;
  }

  /**
   * Authenticates with the provided username and password via KeyCloak to get a KeyCloak token
   * Generates a TazamaToken from the KeyCloak Token with added claims and tenant information
   */
  async getToken(username: string, password: string): Promise<string> {
    const form = new URLSearchParams();
    form.append('client_id', iKeycloakConfig1.keycloakConfig.clientID as string);
    form.append('client_secret', iKeycloakConfig1.keycloakConfig.clientSecret as string);
    form.append('username', username);
    form.append('password', password);
    form.append('grant_type', 'password');
    const myHeaders = new Headers();
    myHeaders.append('Content-Type', 'application/x-www-form-urlencoded');
    const res = await fetch(`${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`, {
      method: 'POST',
      body: form,
      headers: myHeaders,
      redirect: 'follow',
    });
    const resBody = JSON.parse(await res.text());
    const token = {
      accessToken: resBody.access_token,
      tokenType: resBody.token_type,
      refreshToken: resBody.refresh_token,
    };
    return authLib1.JwtService.signToken(await this.generateTazamaToken(token));
  }
  /**
   * Decodes the given Keycloak authentication token and maps out the associated claims with tenant info.
   */
  async generateTazamaToken(authToken: KeycloakAuthToken): Promise<string> {
    const decodedToken = jsonwebtoken1.default.decode(authToken.accessToken);

    // Ensure decodedToken is not a string or undefined and is of type KeycloakJwtToken
    if (!decodedToken || typeof decodedToken === 'string') {
      throw new Error(`Token is in the wrong format, received ${typeof decodedToken}`);
    }

    // Type assertion: safely cast decodedToken to KeycloakJwtToken
    const decodedTokenTyped = decodedToken as KeycloakJwtToken;

    // Ensure required fields are present in the decoded token
    if (!decodedTokenTyped.sub || !decodedTokenTyped.iss || !decodedTokenTyped.exp) {
      throw new Error(
        `Token is missing required properties: sub: ${decodedTokenTyped.sub}, iss: ${decodedTokenTyped.iss}, exp: ${decodedTokenTyped.exp}`,
      );
    }

    // Now you can safely use the typed decodedToken
    return JSON.stringify({
      clientId: decodedTokenTyped.sub,
      iss: decodedTokenTyped.iss,
      sid: decodedTokenTyped.sid,
      exp: decodedTokenTyped.exp,
      tokenString: authToken.accessToken,
      claims: this.mapTazamaRoles(decodedTokenTyped), // Pass the typed token here
      tenantId: decodedTokenTyped.tenant_id,
    });
  }

  /**
   * Extracts and maps the claims from the decoded Keycloak JWT token.
   */
  mapTazamaRoles(decodedToken: KeycloakJwtToken): string[] {
    const roles = [];
    for (const res in decodedToken.resource_access) {
      for (const role of decodedToken.resource_access[res].roles) {
        roles.push(role);
      }
    }
    if (decodedToken.realm_access) {
      for (const role of decodedToken.realm_access.roles) {
        roles.push(role);
      }
    }
    return roles;
  }
}
// export { KeycloakProvider };
export { KeycloakProvider };
//# sourceMappingURL=provider.js.map
