const adminBase = (baseUrl: string, realm: string): string => `${baseUrl}/admin/realms/${realm}`;

export const KEYCLOAK_TOKEN_ENDPOINT = (baseUrl: string, realm: string): string =>
  `${baseUrl}/realms/${realm}/protocol/openid-connect/token`;

export const KEYCLOAK_GROUP_SEARCH_ENDPOINT = (baseUrl: string, realm: string, userGroup: string): string =>
  `${adminBase(baseUrl, realm)}/groups?search=${encodeURIComponent(userGroup)}&briefRepresentation=false`;

export const KEYCLOAK_GROUPS_ENDPOINT = (baseUrl: string, realm: string): string => `${adminBase(baseUrl, realm)}/groups`;

export const KEYCLOAK_GROUP_MEMBERS_ENDPOINT = (baseUrl: string, realm: string, groupId: string): string =>
  `${adminBase(baseUrl, realm)}/groups/${groupId}/members`;

export const KEYCLOAK_SUBGROUPS_ENDPOINT = (baseUrl: string, realm: string, groupId: string): string =>
  `${adminBase(baseUrl, realm)}/groups/${groupId}/children?briefRepresentation=false&max=100`;

export const KEYCLOAK_USERS_ENDPOINT = (baseUrl: string, realm: string): string => `${adminBase(baseUrl, realm)}/users`;

export const KEYCLOAK_SUBGROUP_MEMBERS_ENDPOINT = (baseUrl: string, realm: string, subGroupId: string): string =>
  `${adminBase(baseUrl, realm)}/groups/${subGroupId}/members?briefRepresentation=false`;
