import mongoose, { type Mongoose } from 'mongoose';

export function createDatabaseService(client: Mongoose) {
  let connectionPromise: Promise<Mongoose> | undefined;
  let closePromise: Promise<void> | undefined;

  async function connectDatabase(databaseUrl: string): Promise<Mongoose> {
    if (closePromise) {
      await closePromise;
    }

    if (client.connection.readyState === 1) {
      return client;
    }

    if (connectionPromise) {
      return connectionPromise;
    }

    connectionPromise = client.connect(databaseUrl, { autoIndex: false }).catch((error: unknown) => {
      connectionPromise = undefined;
      throw error;
    });

    return connectionPromise;
  }

  async function checkDatabaseConnection(): Promise<boolean> {
    const database = client.connection.db;
    if (client.connection.readyState !== 1 || !database) {
      return false;
    }

    try {
      await database.command({ ping: 1 });
      return true;
    } catch {
      return false;
    }
  }

  async function closeDatabase(): Promise<void> {
    if (closePromise) {
      return closePromise;
    }

    closePromise = (async () => {
      if (connectionPromise) {
        try {
          await connectionPromise;
        } catch {
          // A failed connection attempt has no open connection to close.
        }
      }

      if (client.connection.readyState !== 0) {
        await client.disconnect();
      }
    })();

    try {
      await closePromise;
    } finally {
      connectionPromise = undefined;
      closePromise = undefined;
    }
  }

  return { connectDatabase, checkDatabaseConnection, closeDatabase };
}

const databaseService = createDatabaseService(mongoose);

export const { connectDatabase, checkDatabaseConnection, closeDatabase } = databaseService;
