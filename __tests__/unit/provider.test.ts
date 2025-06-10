import { validateTokenAndClaims } from '@tazama-lf/auth-lib';
import fs from 'fs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { keycloakConfig } from '../../src/interfaces/iKeycloakConfig';
import { KeycloakProvider } from '../../src/provider';

jest.mock('fs');

const mockKeycloakAuthToken = {
  access_token:
    'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJacDJINEtReVBFUW9oMWQwRTVSZzdnaThBeUQzeGVLNWpPSjdTX3BBYkpFIn0.eyJleHAiOjE3MjIyNTU4ODMsImlhdCI6MTcyMjI1NTU4MywianRpIjoiYzZiZDc5NjQtZDRlZS00OWQ5LWFlYzktZTA3NWU1N2E2OTAxIiwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo4MDgwL3JlYWxtcy90YXphbWEiLCJhdWQiOiJhY2NvdW50Iiwic3ViIjoiM2U1ZjQ5MjYtYjVjMi00YjQ2LTk0OTItNjQwYzg1YTcwZDM5IiwidHlwIjoiQmVhcmVyIiwiYXpwIjoiYXV0aC1saWItY2xpZW50Iiwic2Vzc2lvbl9zdGF0ZSI6IjIxNTdiNjNhLTFjZWQtNDQ0Mi04YjNiLTMyZjg2OTFkYTdkNSIsImFjciI6IjEiLCJhbGxvd2VkLW9yaWdpbnMiOlsiLyoiXSwicmVhbG1fYWNjZXNzIjp7InJvbGVzIjpbIlBPU1RfVjFfRVZBTFVBVEVfSVNPMjAwMjJfUEFJTl8wMDFfMDAxXzExIiwiUE9TVF9WMV9FVkFMVUFURV9JU08yMDAyMl9QQUNTXzAwOF8wMDFfMTAiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBQ1NfMDAyXzAwMV8xMiIsImRlZmF1bHQtcm9sZXMtdGF6YW1hIiwib2ZmbGluZV9hY2Nlc3MiLCJQT1NUX1YxX0VWQUxVQVRFX0lTTzIwMDIyX1BBSU5fMDEzXzAwMV8wOSIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJlbWFpbCBwcm9maWxlIiwic2lkIjoiMjE1N2I2M2EtMWNlZC00NDQyLThiM2ItMzJmODY5MWRhN2Q1IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsInByZWZlcnJlZF91c2VybmFtZSI6InRhemFtYS11c2VyIiwiZW1haWwiOiJ0YXphbWEtdXNlckBleGFtcGxlLmNvbSJ9.V5r6U2pS80OeSVNKbXZzHyli2GD3oITki5FaQbTV8DtGm9SF8tE2E-8KvZ5I0mtH5m9VCmFNuaR_8ODol_obGiRG1R-1J_hajxEI_BgBybFByxOX5HQPUnr4xTZrHqtzbBk1tv711SrYuqJHhrslxCG1dE3CI32JXF-HhDoXTGllrkpWKiRfe9hrbQg52-X06buBeCcRT6FU860tq-NciXB73RkyBpKhRGaImt53xZyLb_lpz-ZOkD63euOvAUEJNQQdHG-VauHov6VixUAmLmps5havozh3998sX6vhtSnBnRQXfonLJowh6I4R2ibhkAYrJeokf_MBHqUwmv8I2g',
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
