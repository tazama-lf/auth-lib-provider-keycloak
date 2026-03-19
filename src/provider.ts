import type { KeycloakAuthToken, KeycloakJwtToken } from './interfaces/iKeycloakToken';
import { JwtService, type TazamaAuthProvider, type TazamaToken, type TazamaUser } from '@tazama-lf/auth-lib';
import jwt from 'jsonwebtoken';
import { keycloakConfig } from './interfaces/iKeycloakConfig';
import type { KeycloakGroup, KeycloakSubGroup, KeycloakGroupMember } from './interfaces/iKeycloakGroup';
import {
  KEYCLOAK_GROUP_SEARCH_ENDPOINT,
  KEYCLOAK_SUBGROUPS_ENDPOINT,
  KEYCLOAK_SUBGROUP_MEMBERS_ENDPOINT,
  KEYCLOAK_TOKEN_ENDPOINT,
} from './utils/constants';
import { fetchWithAuth } from './utils/helper';

const ZERO = 0;

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
    const res = await fetch(KEYCLOAK_TOKEN_ENDPOINT(this.baseUrl, this.realm), {
      method: 'POST',
      body: form,
      headers: myHeaders,
      redirect: 'follow',
    });

    const resBody = JSON.parse(await res.text()) as { access_token: string; token_type: string; refresh_token: string };

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

  /**
   * Fetches user group details from Keycloak admin API based on group name search
   *
   * @param {string} tokenString - The access token string for authorization
   * @param {string} userGroup - The group name to search for
   * @returns {Promise<KeycloakGroup[]>} - A promise that resolves to an array of matching groups
   */
  async fetchUserGroupDetails(decodedToken: TazamaToken, userGroup: string): Promise<KeycloakGroup[]> {
    try {
      const response = await fetchWithAuth(KEYCLOAK_GROUP_SEARCH_ENDPOINT(this.baseUrl, this.realm, userGroup), decodedToken.tokenString);
      const groupDetails = response as KeycloakGroup[];
      return groupDetails;
    } catch (error) {
      const err = error as Error;
      throw new Error('fetchUserGroupDetails retrieval failed', { cause: err });
    }
  }

  /**
   * Fetches sub-groups (children) of a specific group from Keycloak admin API
   *
   * @param {string} tokenString - The access token string for authorization
   * @param {string} groupId - The parent group ID
   * @returns {Promise<KeycloakSubGroup[]>} - A promise that resolves to an array of sub-groups
   */
  async fetchSubGroups(decodedToken: TazamaToken, groupId: string): Promise<KeycloakSubGroup[]> {
    try {
      const response = await fetchWithAuth(KEYCLOAK_SUBGROUPS_ENDPOINT(this.baseUrl, this.realm, groupId), decodedToken.tokenString);
      const subGroupDetails = response as KeycloakSubGroup[];
      return subGroupDetails;
    } catch (error) {
      const err = error as Error;
      throw new Error('fetchSubGroups retrieval failed', { cause: err });
    }
  }

  /**
   * Fetches members of a specific group from Keycloak admin API
   *
   * @param {string} tokenString - The access token string for authorization
   * @param {string} groupId - The group ID to fetch members from
   * @returns {Promise<KeycloakGroupMember[]>} - A promise that resolves to an array of group members
   */
  async fetchSubGroupMembers(decodedToken: TazamaToken, subGroupId: string): Promise<KeycloakGroupMember[]> {
    try {
      const response = await fetchWithAuth(
        KEYCLOAK_SUBGROUP_MEMBERS_ENDPOINT(this.baseUrl, this.realm, subGroupId),
        decodedToken.tokenString,
      );
      const members = response as KeycloakGroupMember[];
      return members;
    } catch (error) {
      const err = error as Error;
      throw new Error(`fetchSubGroupMembers retrieval failed: ${err.message}`);
    }
  }

  /**
   * Fetches users by role from Keycloak groups with tenant filtering
   *
   * @param {TazamaToken} decodedToken - The decoded Tazama token containing tenant information
   * @param {string} groupName - The name of the group to search for
   * @param {string} [subGroupRoleName] - Optional sub-group/role name to filter by
   * @returns {Promise<KeycloakGroupMember[]>} - A promise that resolves to an array of group members
   */
  async fetchUsersByRole(decodedToken: TazamaToken, userGroup: string, roleName: string): Promise<TazamaUser[]> {
    const FIRST_INDEX = 0;
    try {
      const groupDetails = await this.fetchUserGroupDetails(decodedToken, userGroup);

      if (groupDetails.length === ZERO) {
        throw new Error(`No group found with the group name: ${userGroup}`);
      }
      const subGroups = await this.fetchSubGroups(decodedToken, groupDetails[FIRST_INDEX].id ?? '');
      const subGroupId = subGroups.find((group: KeycloakSubGroup) => group.realmRoles?.includes(roleName))?.id;
      if (!subGroupId) {
        throw new Error(`No sub-group found with role: ${roleName}`);
      }
      const subGroupMembers = await this.fetchSubGroupMembers(decodedToken, subGroupId);
      return subGroupMembers.map((member) => this.mapToTazamaUser(member));
    } catch (error) {
      const err = error as Error;
      throw new Error('getUsersByRole retrieval failed', { cause: err });
    }
  }

  private mapToTazamaUser(keyCloakUser: KeycloakGroupMember): TazamaUser {
    return {
      id: keyCloakUser.id,
      username: keyCloakUser.username,
      firstName: keyCloakUser.firstName,
      lastName: keyCloakUser.lastName,
      email: keyCloakUser.email,
      emailVerified: keyCloakUser.emailVerified,
      enabled: keyCloakUser.enabled,
      createdTimestamp: keyCloakUser.createdTimestamp,
      metadata: {
        totp: keyCloakUser.totp,
        disableableCredentialTypes: keyCloakUser.disableableCredentialTypes,
        requiredActions: keyCloakUser.requiredActions,
        notBefore: keyCloakUser.notBefore,
      },
    };
  }
}
export { KeycloakProvider };
