import { Capacitor } from '@capacitor/core';

export class BluetoothIntegrationNotConfiguredError extends Error {
  constructor() {
    super('La integración BLE nativa de PICHU todavía no está configurada.');
    this.name = 'BluetoothIntegrationNotConfiguredError';
  }
}

export interface BluetoothService {
  isAvailable(): boolean;
  connect(): Promise<void>;
}

export const bluetoothService: BluetoothService = {
  isAvailable(): boolean {
    return Capacitor.isPluginAvailable('BluetoothLe');
  },

  async connect(): Promise<void> {
    throw new BluetoothIntegrationNotConfiguredError();
  },
};
