import mongoose, { type Mongoose } from 'mongoose';
export function createDatabaseService(client: Mongoose) {
  let connecting: Promise<Mongoose> | undefined;
  let closing: Promise<void> | undefined;
  async function connectDatabase(url: string) {
    if (closing) await closing;
    if (client.connection.readyState === 1) return client;
    if (!connecting)
      connecting = client.connect(url, { autoIndex: false }).catch((error) => {
        connecting = undefined;
        throw error;
      });
    return connecting;
  }
  async function closeDatabase() {
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
  return { connectDatabase, closeDatabase };
}
export const { connectDatabase, closeDatabase } = createDatabaseService(mongoose);
