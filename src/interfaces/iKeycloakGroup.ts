export interface KeycloakGroupAccess {
  view: boolean;
  viewMembers: boolean;
  manageMembers: boolean;
  manage: boolean;
  manageMembership: boolean;
}

export interface GroupAttribute {
  TENANT_ID: string[];
}

export interface KeycloakGroup {
  id: string;
  name: string;
  description: string;
  path: string;
  subGroupCount: number;
  subGroups: KeycloakGroup[];
  access: KeycloakGroupAccess;
  attributes: GroupAttribute;
}

export interface KeycloakSubGroup extends KeycloakGroup {
  parentId: string;
  attributes: GroupAttribute;
  realmRoles: string[];
  clientRoles: Record<string, string[]>;
}

export interface KeycloakGroupMember {
  id: string;
  username: string;
  firstName?: string;
  lastName?: string;
  email?: string;
  emailVerified: boolean;
  enabled: boolean;
  createdTimestamp: number;
  totp: boolean;
  disableableCredentialTypes: string[];
  requiredActions: string[];
  notBefore: number;
}
