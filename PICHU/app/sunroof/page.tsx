'use client';

import { ArrowDown, ArrowLeft, ArrowUp, Info, Square } from 'lucide-react';
import { useRouter } from 'next/navigation';
import { DesktopNavigation } from '@/components/navigation/bottom-navigation';
import { ActionButton, ConnectionBadge, ScreenFrame } from '@/components/pichu-ui';
import { SunroofDiagram } from '@/features/sunroof/sunroof-diagram';
import { useSunroof } from '@/features/sunroof/sunroof-context';

export default function SunroofPage() {
  const router = useRouter();
  const { status, label, isMoving, open, close, stop } = useSunroof();
  const stateColor =
    status === 'opening' || status === 'closing'
      ? 'bg-gold'
      : status === 'open'
        ? 'bg-primary'
        : 'bg-muted-foreground';

  return (
    <ScreenFrame safeAreaTop>
      <div className="hidden justify-end lg:flex">
        <DesktopNavigation />
      </div>
      <div className="flex min-h-12 items-center gap-2 sm:gap-[11px]">
        <button
          type="button"
          aria-label="Volver"
          onClick={() => router.back()}
          className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-border text-foreground transition-colors hover:bg-secondary"
        >
          <ArrowLeft aria-hidden="true" size={18} />
        </button>
        <div className="min-w-0 flex-1">
          <p className="text-[8px] font-semibold tracking-[1px] text-muted-foreground">MAZDA 3 · 2011</p>
          <h1 className="text-sm font-bold sm:text-base">Control del sunroof</h1>
        </div>
        <ConnectionBadge />
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)] lg:items-stretch lg:gap-6">
        <div className="flex min-w-0 flex-col gap-4">
          <section
            aria-live="polite"
            className="flex min-h-[72px] items-center justify-between rounded-[15px] border border-border bg-card px-4 sm:px-5"
          >
            <span className="flex items-center gap-2 text-[9px] font-semibold tracking-[0.8px] text-muted-foreground">
              <span className={`size-[7px] rounded-full ${stateColor}`} />
              ESTADO ACTUAL
            </span>
            <span className="text-[17px] font-bold">{label}</span>
          </section>

          <SunroofDiagram status={status} />
        </div>

        <div className="flex flex-col justify-center gap-4">
          <div className="flex flex-col gap-[9px]">
            <div className="flex gap-[9px]">
              <ActionButton
                title="ABRIR"
                icon={ArrowUp}
                onClick={open}
                disabled={status === 'open' || status === 'opening'}
              />
              <ActionButton
                title="CERRAR"
                icon={ArrowDown}
                variant="secondary"
                onClick={close}
                disabled={status === 'closed' || status === 'closing'}
              />
            </div>
            <ActionButton
              title={isMoving ? 'DETENER MOVIMIENTO' : 'DETENER'}
              icon={Square}
              variant="outline"
              onClick={stop}
              disabled={!isMoving}
            />
          </div>

          <p className="flex items-start gap-2 rounded-xl border border-border bg-card p-4 text-[10px] leading-4 text-muted-foreground">
            <Info aria-hidden="true" size={14} className="mt-0.5 shrink-0 text-gold" />
            Vista local. No hay conexión Bluetooth activa.
          </p>
        </div>
      </div>
    </ScreenFrame>
  );
}
