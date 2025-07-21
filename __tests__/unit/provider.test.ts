import { validateTokenAndClaims } from '@tazama-lf/auth-lib';
import fs from 'fs';
import jwt, { JwtPayload } from 'jsonwebtoken';
import { keycloakConfig } from '../../src/interfaces/iKeycloakConfig';
import { KeycloakProvider } from '../../src/provider';

jest.mock('fs');

const mockKeycloakAuthToken = {
  access_token:
    'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbGllbnRJZCI6IjY4NzQ4ODAwLWZjM2EtNDQyNS05NzdjLWVkNThmMWFmYjdjZCIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6ODA4MC9yZWFsbXMvdGF6YW1hIiwic2lkIjoiZjMyMmFkM2YtYTA1MC00MDUwLWI5MzYtMmVkMGU3ODQ3NGQwIiwiZXhwIjoxNzUzMDk0MTQwLCJ0b2tlblN0cmluZyI6ImV5SmhiR2NpT2lKU1V6STFOaUlzSW5SNWNDSWdPaUFpU2xkVUlpd2lhMmxrSWlBNklDSktSWGxIV21kUVExcFJlWEpsYWs5MWJFb3RWSEZ1Umtab2NFcEZRVWRNZUU1M1QydExRbTVmY0VRd0luMC5leUpsZUhBaU9qRTNOVE13T1RReE5EQXNJbWxoZENJNk1UYzFNekE1TXpnME1Dd2lhblJwSWpvaVpqRmlNekk1WlRNdE16aGxNUzAwTkRsaExXRTNabVl0WVdVNU16WmtOV0ZpTVRZd0lpd2lhWE56SWpvaWFIUjBjRG92TDJ4dlkyRnNhRzl6ZERvNE1EZ3dMM0psWVd4dGN5OTBZWHBoYldFaUxDSmhkV1FpT2lKaFkyTnZkVzUwSWl3aWMzVmlJam9pTmpnM05EZzRNREF0Wm1NellTMDBOREkxTFRrM04yTXRaV1ExT0dZeFlXWmlOMk5rSWl3aWRIbHdJam9pUW1WaGNtVnlJaXdpWVhwd0lqb2lZWFYwYUMxc2FXSXRZMnhwWlc1MElpd2ljMlZ6YzJsdmJsOXpkR0YwWlNJNkltWXpNakpoWkRObUxXRXdOVEF0TkRBMU1DMWlPVE0yTFRKbFpEQmxOemcwTnpSa01DSXNJbUZqY2lJNklqRWlMQ0poYkd4dmQyVmtMVzl5YVdkcGJuTWlPbHNpTHlvaVhTd2ljbVZoYkcxZllXTmpaWE56SWpwN0luSnZiR1Z6SWpwYkltUmxabUYxYkhRdGNtOXNaWE10ZEdGNllXMWhJaXdpYjJabWJHbHVaVjloWTJObGMzTWlMQ0pRVDFOVVgxWXhYMFZXUVV4VlFWUkZYMGxUVHpJd01ESXlYMUJCU1U1Zk1ERXpYekF3TVY4d09TSXNJblZ0WVY5aGRYUm9iM0pwZW1GMGFXOXVJbDE5TENKeVpYTnZkWEpqWlY5aFkyTmxjM01pT25zaVlXTmpiM1Z1ZENJNmV5SnliMnhsY3lJNld5SnRZVzVoWjJVdFlXTmpiM1Z1ZENJc0ltMWhibUZuWlMxaFkyTnZkVzUwTFd4cGJtdHpJaXdpZG1sbGR5MXdjbTltYVd4bElsMTlmU3dpYzJOdmNHVWlPaUp3Y205bWFXeGxJR1Z0WVdsc0lpd2ljMmxrSWpvaVpqTXlNbUZrTTJZdFlUQTFNQzAwTURVd0xXSTVNell0TW1Wa01HVTNPRFEzTkdRd0lpd2lkR1Z1WVc1MFgybGtJam9pZEdWdVlXNTBYM1poYkhWbFh6QXdOU0lzSW1WdFlXbHNYM1psY21sbWFXVmtJanAwY25WbExDSm5jbTkxY0hNaU9sc2ljR0Y1YzNseklsMHNJbkJ5WldabGNuSmxaRjkxYzJWeWJtRnRaU0k2SW1GaVpIVnNiR0ZvSWl3aVpXMWhhV3dpT2lKaFltUjFiR3hoYUVCbmJXRnBiQzVqYjIwaWZRLk95Nnh5YzdPaFpqSnQyZVZpelZPM1oyTXVZS0QyVm5aWHZqLVdnQjFkY2Zvc2RtQ3pvUmxMM19XWWM1TUxDcm1fQ1p4YkhxNk1vUEVtS1FRM0pLZlppU1V6MlFNVWNoeTBWSjdQcHBiYXRSb0xuNE5oZDkycXRaMkdXcnFxMkNLaHRZbVd6YVR1R0dfbTBHbEx2eEtWb2cwQzJjYVR5bVJmczlLLXA0ZmtXVlMtZjZtMmN6d19qTXdrUjB5ZFVtUzE5ZTZtdUlSWDlfQS1HZWFBRm5taTdGajM3TUoxRFQ5REhCWUFYRm9kVUJHQTNROWl0dkF5aEVyb01BT01PWFN5MnhWSXdiNU52LWhSQVphT2g0clNQaFFCTDhUV2Z5NUZJZ0trLVU1SFl0ZWhhd3o1TVhuWFp1eWZBOHRjNFY2Mk1hWmFmLVpJcGJxRE00TTQybGhiQSIsImNsYWltcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIiwiZGVmYXVsdC1yb2xlcy10YXphbWEiLCJvZmZsaW5lX2FjY2VzcyIsIlBPU1RfVjFfRVZBTFVBVEVfSVNPMjAwMjJfUEFJTl8wMTNfMDAxXzA5IiwidW1hX2F1dGhvcml6YXRpb24iXSwidGVuYW50SWQiOiJ0ZW5hbnRfdmFsdWVfMDA1IiwiaWF0IjoxNzUzMDkzODQwfQ.eW1hFkc11XSWA0EEgD9oQRaZ79ubMkIMXvPKZSSZULIt9i6HruC_4BuKAb5Dmp9NRpb2paikY-kfg03wgyvO99WiXxnCySAxaADXMGZb_Bv1oFVD3ssXmvolEFAshaFTzMnIgu8zFHdtopc79W4cUuYcuZASa2Ziu9NaA2VTSC8IDd4cPj81kal4PgyEm7iLqPK2zugUqOAStB7OeRjbTiCvp8BsBzl67BSJp7-MP0_D9E5Yxr9TywR_IsQ7cEKG_50Sk_SLtLNKKLZn5mgdyKlF3QgwWTK_ha-bremD9_sqhaYSBw76UtDWVfM7eSB9SK4tAzRM9dvatN94SA9H3g',
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
