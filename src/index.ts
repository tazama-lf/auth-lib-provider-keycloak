import type { TazamaAuthProvider } from '@tazama-lf/auth-lib';
import { KeycloakProvider } from './provider';

const keycloakProvider = new KeycloakProvider();

function register(): TazamaAuthProvider<[string, string]> {
  return KeycloakProvider.prototype;
}

export { register, keycloakProvider };
export type {
  KeycloakGroup,
  KeycloakSubGroup,
  KeycloakGroupMember,
  KeycloakGroupAccess,
  GroupAttribute,
} from './interfaces/iKeycloakGroup';
export type { iKeycloakConfig } from './interfaces/iKeycloakConfig';
export type { KeycloakJwtToken, KeycloakAuthToken } from './interfaces/iKeycloakToken';
