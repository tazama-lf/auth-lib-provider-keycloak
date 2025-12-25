import type { KeycloakAuthToken, KeycloakJwtToken } from './interfaces/iKeycloakToken';
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
   * Gets an admin access token for Keycloak Admin API calls
   * @returns {Promise<string>} - Admin access token
   */
  async getAdminToken(): Promise<string> {
    const form = new URLSearchParams();
    form.append('client_id', keycloakConfig.clientID);
    form.append('client_secret', keycloakConfig.clientSecret);
    form.append('grant_type', 'client_credentials');
    const res = await fetch(`${this.baseUrl}/realms/${this.realm}/protocol/openid-connect/token`, {
      method: 'POST',
      body: form,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    });
    const resBody = (await res.json()) as { access_token: string };
    return resBody.access_token;
  }

  /**
   * Checks brute force detection status for a user
   * @param {string} userId - The user ID to check
   * @returns {Promise<Object>} - Brute force detection info
   */
  async getBruteForceStatus(userId: string): Promise<{ disabled: boolean; lastFailure?: number }> {
    const adminToken = await this.getAdminToken();
    const res = await fetch(`${this.baseUrl}/admin/realms/${this.realm}/attack-detection/brute-force/users/${userId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
    });
    if (!res.ok) {
      throw new Error(`Failed to get brute force status: ${res.statusText}`);
    }
    return (await res.json()) as { disabled: boolean; lastFailure?: number };
  }

  /**
   * Gets user by username to retrieve userId
   * @param {string} username - The username to search for
   * @returns {Promise<Object>} - User object
   */
  async getUserByUsername(username: string): Promise<{ id: string } | undefined> {
    const adminToken = await this.getAdminToken();
    const res = await fetch(`${this.baseUrl}/admin/realms/${this.realm}/users?username=${encodeURIComponent(username)}&exact=true`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${adminToken}`,
        'Content-Type': 'application/json',
      },
    });
    const users = (await res.json()) as Array<{ id: string }>;
    return users[0];
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

    const resBody = JSON.parse(await res.text()) as {
      access_token: string;
      token_type: string;
      refresh_token: string;
      error?: string;
      error_description?: string;
    };

    if (!res.ok) {
      try {
        const user = await this.getUserByUsername(username);
        if (user?.id) {
          const bruteForceStatus = await this.getBruteForceStatus(user.id);

          if (bruteForceStatus.disabled) {
            throw new Error('Account temporarily locked due to too many failed login attempts.');
          }
        }
      } catch (adminError) {
        if (
          adminError instanceof Error &&
          (adminError.message.includes('Invalid Credentials') || adminError.message.includes('Account temporarily locked'))
        ) {
          throw adminError;
        }
      }

      if (resBody.error === 'invalid_grant') {
        throw new Error('Invalid Credentials');
      }

      throw new Error(resBody.error_description ?? 'Authentication failed');
    }

    const token: KeycloakAuthToken = {
      accessToken: resBody.access_token,
      tokenType: resBody.token_type,
      refreshToken: resBody.refresh_token,
    };

    return JwtService.signToken(this.generateTazamaToken(token));
  }
  /**
   * Decodes the given Keycloak authentication token and maps out the associated claims.
   *
   * @param {KeycloakAuthToken} authToken - The Keycloak authentication token to decode.
   * @returns {Promise<TazamaToken>} - A promise that resolves to a TazamaToken object containing the mapped claims.
   */
  generateTazamaToken(authToken: KeycloakAuthToken): TazamaToken {
    const decoded = jwt.decode(authToken.accessToken);

    // Ensure decodedToken is not a string or undefined and is of type KeycloakJwtToken
    if (!decoded || typeof decoded === 'string') {
      throw new Error(`Token is in the wrong format, received ${typeof decoded}`);
    }
    const decodedToken: KeycloakJwtToken = decoded as KeycloakJwtToken;

    // Ensure required fields are present in the decoded token
    if (!decodedToken.sub || !decodedToken.iss || !decodedToken.exp) {
      throw new Error(`Token is missing required properties: sub: ${decodedToken.sub}, iss: ${decodedToken.iss}, exp: ${decodedToken.exp}`);
    }

    decodedToken.sid ??= 'auth-lib-provider-keycloak';

    return {
      clientId: decodedToken.sub,
      iss: decodedToken.iss,
      sid: decodedToken.sid as string,
      exp: decodedToken.exp,
      tokenString: authToken.accessToken,
      claims: this.mapTazamaRoles(decodedToken), // Pass the typed token here
      tenantId: decodedToken.tenant_id ?? 'DEFAULT',
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
      if (Object.hasOwn(decodedToken.resource_access, res)) {
        for (const role of decodedToken.resource_access[res].roles) {
          roles.push(role);
        }
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
