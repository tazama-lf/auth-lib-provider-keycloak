import type { TazamaAuthProvider, TazamaToken } from '@tazama-lf/auth-lib';
import { KeycloakProvider } from './provider';
import type { KeycloakGroupMember } from './interfaces/iKeycloakGroup';

function register(): TazamaAuthProvider<[string, string], KeycloakGroupMember[], [TazamaToken, string, string]> {
  return KeycloakProvider.prototype;
}

export { register };
export type {
  KeycloakGroup,
  KeycloakSubGroup,
  KeycloakGroupMember,
  KeycloakGroupAccess,
  GroupAttribute,
} from './interfaces/iKeycloakGroup';
export type { iKeycloakConfig } from './interfaces/iKeycloakConfig';
export type { KeycloakJwtToken, KeycloakAuthToken } from './interfaces/iKeycloakToken';
