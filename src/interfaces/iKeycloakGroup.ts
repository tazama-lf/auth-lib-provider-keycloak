export interface KeycloakGroupAccess {
  view?: boolean;
  viewMembers?: boolean;
  manageMembers?: boolean;
  manage?: boolean;
  manageMembership?: boolean;
}

export interface GroupAttribute {
  TENANT_ID?: string[];
  [key: string]: string[] | undefined;
}

export interface KeycloakGroup {
  id?: string;
  name?: string;
  description?: string;
  path?: string;
  subGroupCount?: number;
  subGroups?: KeycloakSubGroup[];
  access?: KeycloakGroupAccess;
  attributes?: GroupAttribute;
}

export interface KeycloakSubGroup extends KeycloakGroup {
  parentId?: string;
  realmRoles?: string[];
  clientRoles?: Record<string, string[]>;
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
