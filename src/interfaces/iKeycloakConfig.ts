import { config as dotenv } from 'dotenv';
import path from 'node:path';

// Load .env file into process.env if it exists. This is convenient for running locally.
dotenv({
  path: path.resolve(__dirname, '../.env'),
});

interface iKeycloakConfig {
  authURL: string;
  keycloakRealm: string;
  clientSecret: string;
  clientID: string;
}

const keycloakConfig: iKeycloakConfig = {
  authURL: process.env.AUTH_URL!,
  clientSecret: process.env.CLIENT_SECRET!,
  keycloakRealm: process.env.KEYCLOAK_REALM!,
  clientID: process.env.CLIENT_ID!,
};

export { keycloakConfig, type iKeycloakConfig };
