import { type KeycloakAuthToken, type KeycloakJwtToken } from './interfaces/iKeycloakToken';
import { JwtService, type TazamaAuthProvider, type TazamaToken } from '@tazama-lf/auth-lib';
import jwt from 'jsonwebtoken';
import { keycloakConfig } from './interfaces/iKeycloakConfig';

class KeycloakProvider implements TazamaAuthProvider<[string, string]> {
  private readonly realm: string;
  private readonly baseUrl: string;

  constructor() {
    if (!keycloakConfig.keycloakRealm || !keycloakConfig.authURL) {
      throw new Error('Missing realm or URL for Keycloak Provider');
    }
    this.realm = keycloakConfig.keycloakRealm;
    this.baseUrl = keycloakConfig.authURL;
  }

  /**
   * Authenticates with the provided username and password via KeyCloak to get a KeyCloak token
   * Generates a TazamaToken from the KeyCloak Token with added claims
   *
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @returns {Promise<string>} - A promise that resolves to a signed JWT token.
   */
  async getToken(username: string, password: string): Promise<string> {
    const form = new URLSearchParams();
    form.append('client_id', keycloakConfig.clientID);
    form.append('client_secret', keycloakConfig.clientSecret);
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
    const token: KeycloakAuthToken = {
      accessToken: resBody.access_token,
      tokenType: resBody.token_type,
      refreshToken: resBody.refresh_token,
    };
    return JwtService.signToken(await this.generateTazamaToken(token));
  }
  /**
   * Decodes the given Keycloak authentication token and maps out the associated claims.
   *
   * @param {KeycloakAuthToken} authToken - The Keycloak authentication token to decode.
   * @returns {Promise<TazamaToken>} - A promise that resolves to a TazamaToken object containing the mapped claims.
   */
  async generateTazamaToken(authToken: KeycloakAuthToken): Promise<TazamaToken> {
    const decodedToken = jwt.decode(authToken.accessToken);

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
    return {
      clientId: decodedTokenTyped.sub,
      iss: decodedTokenTyped.iss,
      sid: decodedTokenTyped.sid || '',
      exp: decodedTokenTyped.exp,
      tokenString: authToken.accessToken,
      claims: this.mapTazamaRoles(decodedTokenTyped), // Pass the typed token here
      tenantId: decodedTokenTyped.tenant_id ?? 'default',
    };
  }

  /**
   * Extracts and maps the claims from the decoded Keycloak JWT token.
   *
   * @param {KeycloakJwtToken} decodedToken - The decoded JWT token from Keycloak.
   * @returns {string[]} - An array of privileges extracted from the decoded token.
   */
  mapTazamaRoles(decodedToken: KeycloakJwtToken): string[] {
    const roles: string[] = [];
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
export { KeycloakProvider };
