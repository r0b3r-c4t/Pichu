import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import { PwaServiceWorker } from '@/components/pwa-service-worker';
import { SunroofProvider } from '@/features/sunroof/sunroof-context';
import './globals.css';

export const metadata: Metadata = {
  title: {
    default: 'PICHU',
    template: '%s | PICHU',
  },
  description: 'Interfaz de control y administración del vehículo PICHU.',
  manifest: '/manifest.webmanifest',
  icons: {
    icon: [
      { url: '/icons/icon-192.png', sizes: '192x192', type: 'image/png' },
      { url: '/icons/icon-512.png', sizes: '512x512', type: 'image/png' },
    ],
    apple: [{ url: '/icons/apple-touch-icon.png', sizes: '180x180', type: 'image/png' }],
  },
  appleWebApp: {
    capable: true,
    statusBarStyle: 'black-translucent',
    title: 'PICHU',
  },
  other: {
    'apple-mobile-web-app-capable': 'yes',
  },
};

export const viewport: Viewport = {
  themeColor: '#080808',
  viewportFit: 'cover',
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="es">
      <body>
        <SunroofProvider>{children}</SunroofProvider>
        <PwaServiceWorker />
      </body>
    </html>
  );
}
