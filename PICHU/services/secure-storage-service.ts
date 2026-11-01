export interface SecureStorageService {
  get(key: string): Promise<string | null>;
  set(key: string, value: string): Promise<void>;
  remove(key: string): Promise<void>;
}

export class SecureStorageNotConfiguredError extends Error {
  constructor() {
    super('El almacenamiento seguro todavía no está configurado para PICHU.');
    this.name = 'SecureStorageNotConfiguredError';
  }
}

export const secureStorageService: SecureStorageService = {
  async get(): Promise<never> {
    throw new SecureStorageNotConfiguredError();
  },

  async set(): Promise<void> {
    throw new SecureStorageNotConfiguredError();
  },

  async remove(): Promise<void> {
    throw new SecureStorageNotConfiguredError();
  },
};
