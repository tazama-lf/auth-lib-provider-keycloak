import { validateTokenAndClaims } from '@tazama-lf/auth-lib';
import fs from 'fs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { keycloakConfig } from '../../src/interfaces/iKeycloakConfig';
import { KeycloakProvider } from '../../src/provider';

jest.mock('fs');

const mockKeycloakAuthToken = {
  access_token:
    'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJKRXlHWmdQQ1pReXJlak91bEotVHFuRkZocEpFQUdMeE53T2tLQm5fcEQwIn0.eyJleHAiOjE3NTMwOTQxNDAsImlhdCI6MTc1MzA5Mzg0MCwianRpIjoiZjFiMzI5ZTMtMzhlMS00NDlhLWE3ZmYtYWU5MzZkNWFiMTYwIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90YXphbWEiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiNjg3NDg4MDAtZmMzYS00NDI1LTk3N2MtZWQ1OGYxYWZiN2NkIiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYXV0aC1saWItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6ImYzMjJhZDNmLWEwNTAtNDA1MC1iOTM2LTJlZDBlNzg0NzRkMCIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbImRlZmF1bHQtcm9sZXMtdGF6YW1hIiwib2ZmbGluZV9hY2Nlc3MiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBSU5fMDEzXzAwMV8wOSIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiZjMyMmFkM2YtYTA1MC00MDUwLWI5MzYtMmVkMGU3ODQ3NGQwIiwidGVuYW50X2lkIjoidGVuYW50X3ZhbHVlXzAwNSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJncm91cHMiOlsicGF5c3lzIl0sInByZWZlcnJlZF91c2VybmFtZSI6ImFiZHVsbGFoIiwiZW1haWwiOiJhYmR1bGxhaEBnbWFpbC5jb20ifQ.Oy6xyc7OhZjJt2eVizVO3Z2MuYKD2VnZXvj-WgB1dcfosdmCzoRlL3_WYc5MLCrm_CZxbHq6MoPEmKQQ3JKfZiSUz2QMUchy0VJ7PppbatRoLn4Nhd92qtZ2GWrqq2CKhtYmWzaTuGG_m0GlLvxKVog0C2caTymRfs9K-p4fkWVS-f6m2czw_jMwkR0ydUmS19e6muIRX9_A-GeaAFnmi7Fj37MJ1DT9DHBYAXFodUBGA3Q9itvAyhEroMAOMOXSy2xVIwb5Nv-hRAZaOh4rSPhQBL8TWfy5FIgKk-U5HYtehawz5MXnXZuyfA8tc4V62MaZaf-ZIpbqDM4M42lhbA',
  refresh_token: 'TEST_REFRESH_TOKEN',
  token_type: 'Bearer',
  scope: 'TEST',
};

describe('Keycloak Provider', () => {
  const jwtSignVal = 'TEST_SIGN';
  beforeEach(() => {
    jest.spyOn(global, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(mockKeycloakAuthToken))));
    jest.spyOn(fs, 'readFileSync').mockReturnValue(Buffer.from('TEST'));
    jest.spyOn(jwt, 'verify').mockImplementation((x) => jwt.decode(x));
    jest.spyOn(jwt, 'sign').mockImplementation(() => jwtSignVal);

    keycloakConfig.authURL = 'testUrl';
    keycloakConfig.keycloakRealm = 'testRealm';
  });

  it('should handle getToken from Keycloak provider - happy path', async () => {
    const provider = new KeycloakProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    const token = await provider.getToken('testUser', 'testPassword');

    expect(providerSpy).toHaveBeenCalledTimes(1);
    expect(token).toEqual(jwtSignVal);
  });

  it('should handle error on missing config from Keycloak provider', async () => {
    keycloakConfig.authURL = '';
    keycloakConfig.keycloakRealm = '';

    try {
      new KeycloakProvider();
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Missing realm or URL for Keycloak Provider'));
    }
  });

  it('should handle getToken from Keycloak provider - bad decode', async () => {
    jest.spyOn(jwt, 'decode').mockImplementation((x) => 'BAD_TEST_STRING');

    const provider = new KeycloakProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    try {
      await provider.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Token is in the wrong format, received string'));
    }

    expect(providerSpy).toHaveBeenCalledTimes(1);
  });

  it('should handle getToken from Keycloak provider - missing jwt properties', async () => {
    jest.spyOn(jwt, 'decode').mockImplementationOnce((x) => {
      return {
        sub: undefined,
        iss: undefined,
        exp: undefined,
      } as JwtPayload;
    });

    const provider = new KeycloakProvider();

    const providerSpy = jest.spyOn(provider, 'getToken');
    try {
      await provider.getToken('testUser', 'testPassword');
      throw new Error('UNREACHABLE');
    } catch (err) {
      expect(err).toEqual(new Error('Token is missing required properties: sub: undefined, iss: undefined, exp: undefined'));
    }

    expect(providerSpy).toHaveBeenCalledTimes(1);

    jest.spyOn(jwt, 'decode').mockRestore();
  });

  it('should handle token with missing optional fields (sid, tenant_id)', async () => {
    jest.spyOn(jwt, 'decode').mockImplementationOnce(() => {
      return {
        sub: '687488800-fc3a-4425-977c-ed58f1afb7cd', // Required field
        iss: 'http://localhost:8080/realms/tazama', // Required field
        exp: 1753094140, // Required field
        // sid and tenant_id are missing to test fallback values
        resource_access: {
          account: { roles: ['manage-account'] },
        },
        realm_access: {
          roles: ['default-roles-tazama'],
        },
      } as JwtPayload;
    });

    const provider = new KeycloakProvider();
    const token = await provider.getToken('testUser', 'testPassword');

    expect(token).toEqual(jwtSignVal);
    jest.spyOn(jwt, 'decode').mockRestore();
  });

  it('should handle token without realm_access', async () => {
    jest.spyOn(jwt, 'decode').mockImplementationOnce(() => {
      return {
        sub: '687488800-fc3a-4425-977c-ed58f1afb7cd',
        iss: 'http://localhost:8080/realms/tazama',
        sid: 'f322ad3f-a050-4050-b936-2ed0e784742d',
        exp: 1753094140,
        tenant_id: 'tenant_value_005',
        resource_access: {
          account: { roles: ['manage-account', 'view-profile'] },
        },
        // realm_access is missing to test the conditional branch
      } as JwtPayload;
    });

    const provider = new KeycloakProvider();
    const token = await provider.getToken('testUser', 'testPassword');

    expect(token).toEqual(jwtSignVal);
    jest.spyOn(jwt, 'decode').mockRestore();
  });

  it('should handle token without resource_access and realm_access', async () => {
    jest.spyOn(jwt, 'decode').mockImplementationOnce(() => {
      return {
        sub: '687488800-fc3a-4425-977c-ed58f1afb7cd',
        iss: 'http://localhost:8080/realms/tazama',
        sid: 'f322ad3f-a050-4050-b936-2ed0e784742d',
        exp: 1753094140,
        tenant_id: 'tenant_value_005',
        // Both resource_access and realm_access are missing
      } as JwtPayload;
    });

    const provider = new KeycloakProvider();
    const token = await provider.getToken('testUser', 'testPassword');

    expect(token).toEqual(jwtSignVal);
    jest.spyOn(jwt, 'decode').mockRestore();
  });

  it('should get admin token successfully', async () => {
    const mockAdminTokenResponse = {
      access_token: 'admin-token-123',
      token_type: 'Bearer',
    };

    jest.spyOn(global, 'fetch').mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))));

    const provider = new KeycloakProvider();
    const adminToken = await provider.getAdminToken();

    expect(adminToken).toEqual('admin-token-123');
  });

  it('should get user by username successfully', async () => {
    const mockAdminTokenResponse = { access_token: 'admin-token' };
    const mockUserResponse = [{ id: 'user-id-123', username: 'testUser' }];

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockUserResponse))));

    const provider = new KeycloakProvider();
    const user = await provider.getUserByUsername('testUser');

    expect(user?.id).toEqual('user-id-123');
  });

  it('should get brute force status successfully', async () => {
    const mockAdminTokenResponse = { access_token: 'admin-token' };
    const mockBruteForceResponse = { disabled: false, numFailures: 0 };

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockBruteForceResponse))));

    const provider = new KeycloakProvider();
    const status = await provider.getBruteForceStatus('user-id-123');

    expect(status.disabled).toBe(false);
  });

  it('should throw error when brute force status request fails', async () => {
    const mockAdminTokenResponse = { access_token: 'admin-token' };

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response('Not Found', { status: 404, statusText: 'Not Found' })));

    const provider = new KeycloakProvider();

    await expect(provider.getBruteForceStatus('invalid-user')).rejects.toThrow('Failed to get brute force status: Not Found');
  });

  it('should handle authentication failure with invalid credentials', async () => {
    const mockErrorResponse = {
      error: 'invalid_grant',
      error_description: 'Invalid user credentials',
    };

    jest.spyOn(global, 'fetch').mockImplementationOnce(() =>
      Promise.resolve(
        new Response(JSON.stringify(mockErrorResponse), {
          status: 401,
          statusText: 'Unauthorized',
        }),
      ),
    );

    const provider = new KeycloakProvider();

    await expect(provider.getToken('wrongUser', 'wrongPassword')).rejects.toThrow('Invalid Credentials');
  });

  it('should handle authentication failure with account locked', async () => {
    const mockErrorResponse = {
      error: 'invalid_grant',
      error_description: 'Account disabled',
    };
    const mockAdminTokenResponse = { access_token: 'admin-token' };
    const mockUserResponse = [{ id: 'user-id-123' }];
    const mockBruteForceResponse = { disabled: true, lastFailure: Date.now() };

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() =>
        Promise.resolve(
          new Response(JSON.stringify(mockErrorResponse), {
            status: 401,
            statusText: 'Unauthorized',
          }),
        ),
      )
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockUserResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockBruteForceResponse))));

    const provider = new KeycloakProvider();

    await expect(provider.getToken('lockedUser', 'password')).rejects.toThrow(
      'Account temporarily locked due to too many failed login attempts.',
    );
  });

  it('should handle authentication failure with generic error', async () => {
    const mockErrorResponse = {
      error: 'server_error',
      error_description: 'Internal server error',
    };

    jest.spyOn(global, 'fetch').mockImplementationOnce(() =>
      Promise.resolve(
        new Response(JSON.stringify(mockErrorResponse), {
          status: 500,
          statusText: 'Internal Server Error',
        }),
      ),
    );

    const provider = new KeycloakProvider();

    await expect(provider.getToken('testUser', 'testPassword')).rejects.toThrow('Internal server error');
  });

  it('should handle authentication failure when user not found during brute force check', async () => {
    const mockErrorResponse = {
      error: 'invalid_grant',
      error_description: 'Invalid credentials',
    };
    const mockAdminTokenResponse = { access_token: 'admin-token' };
    const mockUserResponse: never[] = [];

    jest
      .spyOn(global, 'fetch')
      .mockImplementationOnce(() =>
        Promise.resolve(
          new Response(JSON.stringify(mockErrorResponse), {
            status: 401,
            statusText: 'Unauthorized',
          }),
        ),
      )
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockAdminTokenResponse))))
      .mockImplementationOnce(() => Promise.resolve(new Response(JSON.stringify(mockUserResponse))));

    const provider = new KeycloakProvider();

    await expect(provider.getToken('nonExistentUser', 'password')).rejects.toThrow('Invalid Credentials');
  });

  it('should handle authentication failure without error description', async () => {
    const mockErrorResponse = {
      error: 'unknown_error',
    };

    jest.spyOn(global, 'fetch').mockImplementationOnce(() =>
      Promise.resolve(
        new Response(JSON.stringify(mockErrorResponse), {
          status: 500,
          statusText: 'Internal Server Error',
        }),
      ),
    );

    const provider = new KeycloakProvider();

    await expect(provider.getToken('testUser', 'testPassword')).rejects.toThrow('Authentication failed');
  });
});

describe('Tazama Auth-lib', () => {
  const testPrivateKeyB64 =
    'LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tDQpNSUlFdkFJQkFEQU5CZ2txaGtpRzl3MEJBUUVGQUFTQ0JLWXdnZ1NpQWdFQUFvSUJBUUN6WkZ0MGlyWUlnRkxyDQpSVnlZYzd0b2RyekQvNllDc2JYS0lONE5tV1F4Y20rS3Nha0xkU3R5aGIzZVA0Q3R6UGhCN0YzRlFJdVJPckJ5DQpCOUdFcm82WmE5cEdKaHN1L25pdWl4QzRFSlI5K2d6ZW5TK01ndmxIcDZvRHRjN0xGMGJmM0JTcFR2UUdwNFNhDQpmN1V4VElETGQzUlZYS1NydVhDYlp1U3NIVUVScGJud2lXVlAvaUNXdkovMU9ub0d5Z0kyVG1QMDl6UHBuYWxiDQpoNVZadzJWVVQwVUxCb1dYUW9VQTQ4N3ZHWW9zQU9FMGVoOUE3TCtaYWFmVTBlTmpCVzQrbk5ZcnErWWFNSW9BDQpSVWxVeEs0anZUTE5SYWFoaFh1eXgvSGg1cDBGdWlIQTFqUllHNjliSzRzbTlGV3hxaVE4MklyVmtrcGNUMGpIDQoxa1NsWktSREFnTUJBQUVDZ2dFQU5GTlZpY3pjQStiS1NPM1djSEZ4ZktzRnJIWHBTbWZqaXEzRGwxdmlxYm1qDQpaMlVpMWNDN2g1QVRMYnlBSURIbFIvVlY5Szg3Qm9XRDZmNzEwaW5JVmwvckx3TDJjdUt1K05wL2FmRU1IeUxNDQpsakpyS0NVYjZSYXl0SnBYVTAzYTBua3pYWjgxOXFydU50S0JXM3ZoSlhnV2FyKzNHSS9pbExHU2lkR09wVUtnDQpyZzFEQjlHVlViQmFOZWY4czBOV2x2NFAyTE9RTnZxcDJ0b1NldWkwYWVkUzA2M1k4bU5oRC9JQUo0K2ZIeVdyDQp0R0JGdW92Vnk4Q283SmpCaWJsVFVIbFRGTmlUVHBXLzJvdHlpNkVNTGdnSVl6Z0pmMEZYN1BsTkNSV0JucDc2DQpsUjkrRGFnTHRuWDJ1VlRJaW5jNFRYZVYvNHNMcjM4ZFpEeEJnNmszQVFLQmdRRGdvTFV5bTJaN0lyRyt3WXpsDQpXaUVkZm5Ua0lKd0hIdTJqTG5ybzAxZjFwQU9aN0NhRWhsOTBXaUhlNDZGQVYrVmtLditXRzF3aEQ3ckhpUXlvDQpPVXF5OHE0bXJqSXhsaVVpcnhpTXEwRW9iNHZhY0pxMWRnaXNtazVXN3lBNFp3V0R0ZDZpOTB1cm9OWCsya0tMDQpOb2RMTmszYWVPc1oyVDBTdEdSV1Z5MVdvUUtCZ1FETWNrenMxclR1dmw5QUNqMmttQmJYMUtrSlAwa0ExUXFLDQoxOFZOemVQUDNINFEyK2dINjJLZCtOWDRmTkoxNEs5bmViUUtDK0tTd2lvRTYyRXhEeDhhaEJBUWF5anNTbitxDQptQnVVcU5LazhqaW15NHdUMW5BRWF3R2o2bkFjNUI4S1RVR09UemJZb0Rsb3ZYWUpzM0JnYjN0N25BSjZxMUVJDQp4REpFM3oya1l3S0JnSEk5NmNuaU5SMjlDRzgrMnR5dW1SYjZBSk1oYnBsRWhwR3VpdjRzdHBpTW9QUkFvVnBYDQpTT2JSREZiaXFGa2tHdHQxN3VVMTV3WTlqTDM4bXI1WDNRRGo0ZVIwUmJ6b1l0eWY5cmxjUTlnLzJ2M3V0UkJEDQpCcWhhRml1cWxGVjdOOWZEd0laYmhWVzFpQUNFbXNGWXF6aDZWdUFkRFZ6cEdtR1A4MVBpSklIaEFvR0FXRGNCDQpoamZtZmhWYW1CRlRJOUFVR3pEQmR5SDlhQVNFdGdBQVBHQVlham9qa3phdjJhcnhOR1NJUHQzdEdidkhNNGpKDQo3SVBRVWE3QjNybUppRmVUL2liNW4zdjlmbWR1eXJjelAyUFE4Q2NyMXB5QlpwWGlZNldnWVkvb3JDNnFUaEdqDQp0Ym5zV25CWUZSK2E3UGltQnBaVDI3UW5SYkxpRmp4QnpJSGU0UzBDZ1lBd2Q0d3lOVEk1MnNXQUx3cW1IV1piDQoxbzVPTkFnMDl5d0Y1YnNNSXVVbDRyS2M1bWxTYjdjaEQyTDlqMzdoSTVVVmpsUGdZT2hpeWZyUHJycXI1NDBFDQpERjVVSDFEUFRJcXVnZjJ1dGZQYjVYVEdrZ3l6Z0JWS0lGS2lMRHFodW0yWW5OdEJnS1NMTDdrVDFJMk5QS3pLDQpNN0ZsM29lZmlSelJwNXV0UkNqMDNBPT0NCi0tLS0tRU5EIFBSSVZBVEUgS0VZLS0tLS0=';
  beforeEach(() => {
    jest.spyOn(jwt, 'sign').mockRestore();
    jest.spyOn(global, 'fetch').mockImplementation(() => Promise.resolve(new Response(JSON.stringify(mockKeycloakAuthToken))));
    jest.spyOn(fs, 'readFileSync').mockReturnValue(Buffer.from(testPrivateKeyB64, 'base64'));
    jest.spyOn(jwt, 'verify').mockImplementation((x) => jwt.decode(x));
  });

  it('should handle validateToken from Tazama Auth-Lib using Keycloak Provider', async () => {
    const provider = new KeycloakProvider();

    const token = await provider.getToken('tazama-user', 'password');

    const claims = ['default-roles-tazama', 'admin-panel'];

    const checkedClaims = validateTokenAndClaims(token, claims);

    expect(checkedClaims['default-roles-tazama']).toBeTruthy();
    expect(checkedClaims['admin-panel']).toBeFalsy();
  });
});
