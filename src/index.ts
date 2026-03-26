import type { TazamaAuthProvider, TazamaToken } from '@tazama-lf/auth-lib';
import { KeycloakProvider, type TazamaUser } from './provider';

function register(): TazamaAuthProvider<[string, string], TazamaUser[], [TazamaToken, string, string]> {
  return KeycloakProvider.prototype;
}

export { register };
