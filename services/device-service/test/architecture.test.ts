import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const repositoryRoot = fileURLToPath(new URL('../../../', import.meta.url));
const deviceSourceRoot = join(repositoryRoot, 'services/device-service/src');

function deviceSources(): Array<{ path: string; source: string }> {
  return readdirSync(deviceSourceRoot, { recursive: true, encoding: 'utf8' })
    .filter((path) => path.endsWith('.ts'))
    .map((path) => ({
      path: path.replaceAll('\\', '/'),
      source: readFileSync(join(deviceSourceRoot, path), 'utf8'),
    }));
}

function workspaceDependencies(packagePath: string): string[] {
  const manifest = JSON.parse(readFileSync(join(repositoryRoot, packagePath), 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return Object.keys({ ...manifest.dependencies, ...manifest.devDependencies }).filter((name) =>
    name.startsWith('@pichu/'),
  );
}

test('device-service never calls vehicle-service: Vehicle -> Device stays acyclic', () => {
  const sources = deviceSources();
  assert.ok(sources.length > 0);
  for (const { path, source } of sources) {
    assert.equal(/vehicle-service\/|@pichu\/vehicle-service/.test(source), false, path);
    assert.equal(/VEHICLE_SERVICE_URL/.test(source), false, path);
    assert.equal(/audience[^\n]*['"]vehicle-service['"]/.test(source), false, path);
    assert.equal(/\bfetch\s*\(/.test(source), false, path);
    assert.equal(/^import (?!type )[^\n]*from ['"]node:https?['"]/m.test(source), false, path);
  }

  const outboundCallers = sources
    .filter(({ source }) => /\binternalJsonRequest\s*\(/.test(source))
    .map(({ path }) => path);
  assert.deepEqual(outboundCallers, ['security/email-verification.ts']);
  const outbound = sources.find(({ path }) => path === 'security/email-verification.ts')!.source;
  assert.match(outbound, /IDENTITY_SERVICE_URL/);
  assert.match(outbound, /'identity-service'/);

  assert.deepEqual(workspaceDependencies('services/device-service/package.json').sort(), [
    '@pichu/contracts',
    '@pichu/internal-auth',
    '@pichu/internal-auth-adapters',
  ]);
  for (const manifest of [
    'services/vehicle-service/package.json',
    'apps/api-gateway/package.json',
    'packages/contracts/package.json',
  ]) {
    const dependencies = workspaceDependencies(manifest);
    assert.equal(dependencies.includes('@pichu/device-service'), false, manifest);
    assert.equal(dependencies.includes('@pichu/vehicle-service'), false, manifest);
    assert.equal(dependencies.includes('@pichu/api-gateway'), false, manifest);
  }
});

test('device-service source never opts out of the Device write guard middleware', () => {
  for (const { path, source } of deviceSources()) {
    const code = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, '');
    assert.equal(/\bmiddleware\s*:/.test(code), false, path);
  }
});
