export const testInternalAuthEnv = {
  INTERNAL_AUTH_ENVIRONMENT: 'test',
  INTERNAL_AUTH_KEYRING_JSON: JSON.stringify([
    {
      environment: 'test',
      sender: 'api-gateway',
      audience: 'vehicle-service',
      keyId: 'gateway-vehicle-test',
      secretBase64Url: Buffer.alloc(32, 21).toString('base64url'),
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
      state: 'active',
    },
    {
      environment: 'test',
      sender: 'api-gateway',
      audience: 'device-service',
      keyId: 'gateway-device-test',
      secretBase64Url: Buffer.alloc(32, 22).toString('base64url'),
      notBefore: 1,
      notAfter: 8_000_000_000_000_000,
      state: 'active',
    },
  ]),
};
