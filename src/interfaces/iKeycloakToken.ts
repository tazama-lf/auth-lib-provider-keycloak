import type { JwtPayload } from 'jsonwebtoken';

interface KeycloakJwtToken extends JwtPayload {
  resource_access?: Record<string, { roles: string[] }>;
  realm_access?: {
    roles: string[];
  };
}

interface KeycloakAuthToken {
  accessToken: string;
  tokenType: string;
  refreshToken: string;
}

export type { KeycloakJwtToken, KeycloakAuthToken };
