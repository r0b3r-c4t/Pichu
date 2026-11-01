'use client';

import { useEffect, useRef, useState } from 'react';
import { RefreshCw, X } from 'lucide-react';
import { platformService } from '@/services/platform-service';

export function PwaServiceWorker() {
  const [waitingWorker, setWaitingWorker] = useState<ServiceWorker | null>(null);
  const [isApplying, setIsApplying] = useState(false);
  const shouldReload = useRef(false);

  useEffect(() => {
    if (
      process.env.NODE_ENV !== 'production' ||
      platformService.isNativePlatform() ||
      !('serviceWorker' in navigator) ||
      (window.location.protocol !== 'https:' && window.location.hostname !== 'localhost')
    ) {
      return;
    }

    let registration: ServiceWorkerRegistration | undefined;
    let isMounted = true;
    const showWaitingWorker = () => {
      if (isMounted && registration?.waiting && navigator.serviceWorker.controller) {
        setWaitingWorker(registration.waiting);
      }
    };

    const handleControllerChange = () => {
      if (shouldReload.current) window.location.reload();
    };

    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && registration) {
        void registration.update().catch((error: unknown) => {
          console.error('PICHU no pudo comprobar actualizaciones de la PWA.', error);
        });
      }
    };

    navigator.serviceWorker.addEventListener('controllerchange', handleControllerChange);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    void navigator.serviceWorker
      .register('/sw.js', { scope: '/', updateViaCache: 'none' })
      .then((serviceWorkerRegistration) => {
        if (!isMounted) return;
        registration = serviceWorkerRegistration;
        showWaitingWorker();
        void registration.update().catch((error: unknown) => {
          console.error('PICHU no pudo comprobar actualizaciones de la PWA.', error);
        });

        registration.addEventListener('updatefound', () => {
          const installingWorker = registration?.installing;
          installingWorker?.addEventListener('statechange', showWaitingWorker);
        });
      })
      .catch((error: unknown) => {
        console.error('PICHU no pudo registrar el service worker.', error);
      });

    return () => {
      isMounted = false;
      navigator.serviceWorker.removeEventListener('controllerchange', handleControllerChange);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  if (!waitingWorker) return null;

  const applyUpdate = () => {
    shouldReload.current = true;
    setIsApplying(true);
    waitingWorker.postMessage({ type: 'SKIP_WAITING' });
  };

  return (
    <aside
      aria-live="polite"
      className="fixed inset-x-3 bottom-[calc(5.5rem+env(safe-area-inset-bottom))] z-30 mx-auto flex max-w-lg items-center gap-3 rounded-2xl border border-border bg-card p-3 shadow-2xl lg:inset-x-auto lg:bottom-4 lg:right-4"
    >
      <p className="min-w-0 flex-1 text-xs leading-5">
        Hay una actualización de PICHU disponible.
      </p>
      <button
        type="button"
        onClick={applyUpdate}
        disabled={isApplying}
        className="flex min-h-11 shrink-0 items-center gap-2 rounded-xl bg-primary px-3 text-xs font-semibold text-primary-foreground disabled:opacity-70"
      >
        <RefreshCw aria-hidden="true" size={15} className={isApplying ? 'animate-spin' : ''} />
        {isApplying ? 'Actualizando' : 'Actualizar'}
      </button>
      <button
        type="button"
        aria-label="Cerrar aviso de actualización"
        onClick={() => setWaitingWorker(null)}
        className="flex size-11 shrink-0 items-center justify-center rounded-xl text-muted-foreground hover:bg-secondary hover:text-foreground"
      >
        <X aria-hidden="true" size={17} />
      </button>
    </aside>
  );
}
