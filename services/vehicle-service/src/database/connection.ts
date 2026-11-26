import mongoose, { type Mongoose } from 'mongoose';

export function createDatabaseService(client: Mongoose) {
  let connecting: Promise<Mongoose> | undefined;
  let closing: Promise<void> | undefined;

  async function connectDatabase(url: string): Promise<Mongoose> {
    if (closing) await closing;
    if (client.connection.readyState === 1) return client;
    if (!connecting) {
      connecting = client.connect(url, { autoIndex: false }).catch((error: unknown) => {
        connecting = undefined;
        throw error;
      });
    }
    return connecting;
  }

  async function checkDatabaseConnection(timeoutMs = 500): Promise<boolean> {
    const database = client.connection.db;
    if (client.connection.readyState !== 1 || !database) {
      return false;
    }

    try {
      const result = await database.command({ ping: 1 }, { timeoutMS: timeoutMs });
      return result.ok === 1;
    } catch {
      return false;
    }
  }

  async function closeDatabase(): Promise<void> {
    if (closing) return closing;
    closing = (async () => {
      if (connecting) await connecting.catch(() => undefined);
      if (client.connection.readyState !== 0) await client.disconnect();
    })();
    try {
      await closing;
    } finally {
      connecting = undefined;
      closing = undefined;
    }
  }

  return { connectDatabase, checkDatabaseConnection, closeDatabase };
}

export const { connectDatabase, checkDatabaseConnection, closeDatabase } =
  createDatabaseService(mongoose);
