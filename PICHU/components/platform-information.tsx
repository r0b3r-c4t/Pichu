'use client';

import { useSyncExternalStore } from 'react';
import { AppWindow, Smartphone } from 'lucide-react';
import { InfoRow } from '@/components/pichu-ui';
import { platformService, type PichuPlatform } from '@/services/platform-service';

const platformLabels: Record<PichuPlatform, string> = {
  android: 'Aplicación nativa · Android',
  ios: 'Aplicación nativa · iOS',
  web: 'Navegador web',
};

const subscribe = () => () => {};
const getSnapshot = () => platformService.getPlatform();
const getServerSnapshot = (): PichuPlatform => 'web';

export function PlatformInformation() {
  const platform = useSyncExternalStore(subscribe, getSnapshot, getServerSnapshot);

  return (
    <InfoRow
      icon={platform === 'web' ? AppWindow : Smartphone}
      label="Plataforma"
      value={platformLabels[platform]}
    />
  );
}
