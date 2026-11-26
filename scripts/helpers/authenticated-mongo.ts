import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const docker = (...args: string[]) =>
  run('docker', args, { timeout: 30_000, maxBuffer: 1_048_576 });

export type AuthenticatedMongo = {
  id: string;
  binding: string;
  rootUri: string;
  users: {
    identity: { username: string; password: string; db: 'identity_db' };
    vehicle: { username: string; password: string; db: 'vehicle_db' };
    device: { username: string; password: string; db: 'device_db' };
  };
  uri(service: keyof AuthenticatedMongo['users']): string;
  cleanup(): Promise<void>;
};

export async function startAuthenticatedMongo(): Promise<AuthenticatedMongo> {
  await docker('info', '--format', '{{.ServerVersion}}');
  const id = randomUUID().replaceAll('-', '');
  const container = `pichu-tkt0098e-${id}`;
  const rootUser = `root_${id.slice(0, 8)}`;
  const rootPassword = randomBytes(24).toString('base64url');
  const users = {
    identity: {
      username: 'identity_user',
      password: randomBytes(24).toString('base64url'),
      db: 'identity_db' as const,
    },
    vehicle: {
      username: `vehicle_${id.slice(0, 8)}`,
      password: randomBytes(24).toString('base64url'),
      db: 'vehicle_db' as const,
    },
    device: {
      username: `device_${id.slice(0, 8)}`,
      password: randomBytes(24).toString('base64url'),
      db: 'device_db' as const,
    },
  };
  const userCreation = Object.values(users)
    .map(
      (u) =>
        `db.getSiblingDB("${u.db}").createUser({user:"${u.username}",pwd:"${u.password}",roles:[{role:"readWrite",db:"${u.db}"}]})`,
    )
    .join(';');
  const init = `set -eu
key=/tmp/mongo-keyfile
head -c 756 /dev/urandom | base64 | tr -d '\\n' > "$key"
chmod 400 "$key"
mongod --replSet pichu_test --bind_ip_all --auth --keyFile "$key" --dbpath /data/db --fork --logpath /tmp/mongod.log
for i in $(seq 1 60); do mongosh --quiet --eval 'db.hello().ok' >/dev/null 2>&1 && break; sleep 1; done
mongosh --quiet --eval 'rs.initiate({_id:"pichu_test",members:[{_id:0,host:"localhost:27017"}]})'
for i in $(seq 1 60); do mongosh --quiet --eval 'if (!db.hello().isWritablePrimary) quit(1)' >/dev/null 2>&1 && break; sleep 1; done
mongosh --quiet --eval 'db.getSiblingDB("admin").createUser({user:"${rootUser}",pwd:"${rootPassword}",roles:[{role:"root",db:"admin"}]})'
mongosh --quiet --username "${rootUser}" --password "${rootPassword}" --authenticationDatabase admin --eval 'db.runCommand({ping:1})' >/dev/null
mongosh --quiet --username "${rootUser}" --password "${rootPassword}" --authenticationDatabase admin --eval '${userCreation}'
tail -f /dev/null`;
  let created = false;
  try {
    await docker(
      'run',
      '--detach',
      '--name',
      container,
      '--label',
      `pichu.tkt0098e=${id}`,
      '--publish',
      '127.0.0.1::27017',
      '--tmpfs',
      '/data/db',
      '--tmpfs',
      '/data/configdb',
      'mongo:8.0.17',
      'bash',
      '-ec',
      init,
    );
    created = true;
    let binding = '';
    for (let i = 0; i < 60; i++) {
      try {
        binding = (await docker('port', container, '27017/tcp')).stdout.trim();
        assert.match(binding, /^127\.0\.0\.1:[0-9]+$/);
        break;
      } catch {
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    assert.match(binding, /^127\.0\.0\.1:[0-9]+$/);
    const rootUri = `mongodb://${rootUser}:${encodeURIComponent(rootPassword)}@${binding}/admin?authSource=admin&replicaSet=pichu_test&directConnection=true`;
    for (let i = 0; i < 60; i++) {
      try {
        await docker(
          'exec',
          container,
          'mongosh',
          '--quiet',
          '--username',
          rootUser,
          '--password',
          rootPassword,
          '--authenticationDatabase',
          'admin',
          '--eval',
          'if (!db.hello().isWritablePrimary) quit(1)',
        );
        break;
      } catch {
        if (i === 59) throw new Error('MongoDB administrator authentication did not become ready');
        await new Promise((r) => setTimeout(r, 250));
      }
    }
    for (const service of Object.values(users)) {
      for (let i = 0; i < 60; i++) {
        try {
          await docker(
            'exec',
            container,
            'mongosh',
            '--quiet',
            '--username',
            service.username,
            '--password',
            service.password,
            '--authenticationDatabase',
            service.db,
            '--eval',
            'db.runCommand({ping:1})',
          );
          break;
        } catch {
          if (i === 59)
            throw new Error(`MongoDB ${service.db} authentication did not become ready`);
          await new Promise((r) => setTimeout(r, 250));
        }
      }
    }
    return {
      id,
      binding,
      rootUri,
      users,
      uri(service) {
        const u = users[service];
        return `mongodb://${u.username}:${encodeURIComponent(u.password)}@${binding}/${u.db}?authSource=${u.db}&replicaSet=pichu_test&directConnection=true`;
      },
      async cleanup() {
        await docker('rm', '--force', container).catch(() => undefined);
      },
    };
  } catch (error) {
    if (created) {
      await docker('logs', container)
        .then(({ stdout, stderr }) => {
          const output = `${stdout}\n${stderr}`.trim();
          if (output) console.error(`Mongo bootstrap status: ${output.slice(-2000)}`);
        })
        .catch(() => undefined);
      await docker('rm', '--force', container).catch(() => undefined);
    }
    throw error;
  }
}
