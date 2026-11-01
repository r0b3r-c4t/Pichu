import { Capacitor } from '@capacitor/core';

export type PichuPlatform = 'android' | 'ios' | 'web';

export const platformService = {
  getPlatform(): PichuPlatform {
    const platform = Capacitor.getPlatform();
    return platform === 'android' || platform === 'ios' ? platform : 'web';
  },

  isNativePlatform(): boolean {
    return Capacitor.isNativePlatform();
  },
};
