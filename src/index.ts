import { type TazamaAuthProvider } from '@tazama-lf/auth-lib';
import { KeycloakProvider } from './provider';

function register(): TazamaAuthProvider<[string, string]> {
  return KeycloakProvider.prototype;
}

export { register };
