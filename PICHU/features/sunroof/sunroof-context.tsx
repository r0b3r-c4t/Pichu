'use client';

import {
  createContext,
  type PropsWithChildren,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import type { SunroofStatus } from '@/types/sunroof';

const MOVEMENT_DURATION_MS = 2400;

const labels: Record<SunroofStatus, string> = {
  closed: 'Cerrado',
  open: 'Abierto',
  opening: 'Abriendo',
  closing: 'Cerrando',
  stopped: 'Detenido',
  unknown: 'Desconocido',
};

interface SunroofContextValue {
  status: SunroofStatus;
  label: string;
  isMoving: boolean;
  open: () => void;
  close: () => void;
  stop: () => void;
}

const SunroofContext = createContext<SunroofContextValue | null>(null);

export function SunroofProvider({ children }: PropsWithChildren) {
  const [status, setStatus] = useState<SunroofStatus>('closed');
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const clearMovement = useCallback(() => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
    }
  }, []);

  const beginMovement = useCallback(
    (direction: 'open' | 'close') => {
      clearMovement();
      if (direction === 'open' && status === 'open') return;
      if (direction === 'close' && status === 'closed') return;

      setStatus(direction === 'open' ? 'opening' : 'closing');
      timer.current = setTimeout(() => {
        setStatus(direction === 'open' ? 'open' : 'closed');
        timer.current = null;
      }, MOVEMENT_DURATION_MS);
    },
    [clearMovement, status],
  );

  const open = useCallback(() => beginMovement('open'), [beginMovement]);
  const close = useCallback(() => beginMovement('close'), [beginMovement]);
  const stop = useCallback(() => {
    clearMovement();
    setStatus('stopped');
  }, [clearMovement]);

  useEffect(() => clearMovement, [clearMovement]);

  const value = useMemo(
    () => ({
      status,
      label: labels[status],
      isMoving: status === 'opening' || status === 'closing',
      open,
      close,
      stop,
    }),
    [status, open, close, stop],
  );

  return <SunroofContext.Provider value={value}>{children}</SunroofContext.Provider>;
}

export function useSunroof() {
  const context = useContext(SunroofContext);
  if (!context) {
    throw new Error('useSunroof must be used inside SunroofProvider.');
  }
  return context;
}
