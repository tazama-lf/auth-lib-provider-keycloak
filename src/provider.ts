"use strict";

import { KeycloakAuthToken, KeycloakJwtToken } from "./interfaces/iKeycloakToken";

Object.defineProperty(exports, "__esModule", { value: true });
exports.KeycloakProvider = void 0;
const tslib_1 = require("tslib");
const auth_lib_1 = require("@tazama-lf/auth-lib");
const jsonwebtoken_1 = tslib_1.__importDefault(require("jsonwebtoken"));
const iKeycloakConfig_1 = require("./interfaces/iKeycloakConfig");
class KeycloakProvider {
    realm;
    baseUrl;
    constructor() {
        if (!iKeycloakConfig_1.keycloakConfig.keycloakRealm || !iKeycloakConfig_1.keycloakConfig.authURL) {
            throw new Error('Missing realm or URL for Keycloak Provider');
        }
        this.realm = iKeycloakConfig_1.keycloakConfig.keycloakRealm;
        this.baseUrl = iKeycloakConfig_1.keycloakConfig.authURL;
    }
    /**
     * Get user's own groups using their access token
     */
    // async getUserGroups(userAccessToken) {
    //     console.log(userAccessToken);
    //     console.log(this.baseUrl);
    //     try {
    //         // Use the account API which allows users to access their own information
    //         const response = await fetch(`${this.baseUrl}/realms/${this.realm}/account/groups`, {
    //             method: 'GET',
    //             headers: {
    //                 'Authorization': `Bearer ${userAccessToken}`,
    //                 'Content-Type': 'application/json'
    //             }
    //         });
    //         if (!response.ok) {
    //             console.log(`Failed to get user groups: ${response.status} ${response.statusText}`);
    //             return [];
    //         }
    //         const groups = await response.json();
    //         console.log('groups:', groups);
    //         return groups || [];
    //     } catch (error) {
    //         console.error('Failed to get user groups:', error);
    //         return [];
    //     }
    // }
    /**
     * Get tenant information from user's groups (using their own token)
     */
    // async getTenantInfoFromUserGroups(groups) {
    //     try {
    //         if (!groups || groups.length === 0) {
    //             return { tenant_id: 'default', group_name: null };
    //         }
    //         // Use the first group for tenant information
    //         const primaryGroup = groups[0];
    //         // Extract tenant_id from group attributes FIRST, then fallback to default
    //         const tenantId = primaryGroup.attributes?.['tenant_id']?.[0] || 'default';
    //         return {
    //             tenant_id: tenantId,
    //             group_name: primaryGroup.name,
    //             group_path: primaryGroup.path
    //         };
    //     } catch (error) {
    //         console.error('Failed to extract tenant info from groups:', error);
    //         return { tenant_id: 'default', group_name: null };
    //     }
    // }
    /**
     * Authenticates with the provided username and password via KeyCloak to get a KeyCloak token
     * Generates a TazamaToken from the KeyCloak Token with added claims and tenant information
     */
    async getToken(username: string, password: string) {
        const form = new URLSearchParams();
        form.append('client_id', iKeycloakConfig_1.keycloakConfig.clientID);
        form.append('client_secret', iKeycloakConfig_1.keycloakConfig.clientSecret);
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
        return auth_lib_1.JwtService.signToken(await this.generateTazamaToken(token));
    }
    /**
     * Decodes the given Keycloak authentication token and maps out the associated claims with tenant info.
     */
    async generateTazamaToken(authToken: KeycloakAuthToken) {
        const decodedToken = jsonwebtoken_1.default.decode(authToken.accessToken);
        if (!decodedToken || typeof decodedToken === 'string') {
            throw new Error(`Token is in the wrong format, received ${typeof decodedToken}`);
        }
        if (!decodedToken.sub || !decodedToken.iss || !decodedToken.exp) {
            throw new Error(`Token is missing required properties: sub: ${decodedToken.sub}, iss: ${decodedToken.iss}, exp: ${decodedToken.exp}`);
        }
        // Get tenant information using the user's own token (secure approach)
        // const userGroups = await this.getUserGroups(authToken.accessToken);
        // const tenantInfo = await this.getTenantInfoFromUserGroups(userGroups);
        // console.log(':white_check_mark: USER TOKEN: Got tenant info from user groups API');
        // console.log(':mag: DEBUG: Groups API response:', JSON.stringify(userGroups, null, 2));
        // console.log(':mag: DEBUG: Tenant Info:', tenantInfo);
        return {
            clientId: decodedToken.sub,
            iss: decodedToken.iss,
            sid: decodedToken.sid,
            exp: decodedToken.exp,
            tokenString: authToken.accessToken,
            claims: this.mapTazamaRoles(decodedToken),
            // Add tenant information
            tenantId: decodedToken.tenant_id,
            // group_name: tenantInfo.group_name,
            // group_path: tenantInfo.group_path,
            // groups: decodedToken.groups || []
        };
    }
    /**
     * Extracts and maps the claims from the decoded Keycloak JWT token.
     */
    mapTazamaRoles(decodedToken: KeycloakJwtToken) {
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