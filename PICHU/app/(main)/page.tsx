'use client';

import Link from 'next/link';
import { ArrowUpRight, Sun } from 'lucide-react';
import { useSunroof } from '@/features/sunroof/sunroof-context';
import { CarStage, ModuleRow, ScreenFrame } from '@/components/pichu-ui';

export default function HomePage() {
  const { label } = useSunroof();

  return (
    <ScreenFrame>
      <section className="flex flex-col gap-[5px]">
        <p className="text-[10px] font-semibold tracking-[1.4px] text-gold">TU VEHÍCULO</p>
        <h1 className="text-[31px] font-bold tracking-[-0.8px] sm:text-[36px]">Mazda 3</h1>
        <div className="flex flex-wrap items-center gap-x-[13px] gap-y-2 text-xs text-muted-foreground">
          <span>Sedan · 2011</span>
          <span className="flex items-center gap-1.5">
            <span className="size-[5px] rounded-full bg-gold" />
            Bluetooth sin conexión
          </span>
        </div>
      </section>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.35fr)_minmax(280px,0.8fr)] lg:items-start lg:gap-7">
        <div className="flex min-w-0 flex-col gap-4">
          <CarStage />
          <Link
            href="/sunroof/"
            data-testid="sunroof-summary"
            className="flex min-h-[76px] items-center gap-3 rounded-[15px] border border-border bg-card p-[13px] transition-opacity hover:opacity-80 sm:min-h-[84px] sm:px-4"
          >
            <span className="flex size-[42px] shrink-0 items-center justify-center rounded-xl bg-red-dark">
              <Sun aria-hidden="true" size={19} className="text-primary-foreground" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-sm font-bold">Sunroof</span>
              <span className="mt-1 block text-[11px] text-muted-foreground">Estado · {label}</span>
            </span>
            <span className="flex shrink-0 items-center gap-1 text-[8px] font-bold tracking-wide text-gold">
              CONTROLAR
              <ArrowUpRight aria-hidden="true" size={15} />
            </span>
          </Link>
        </div>
        <section className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <h2 className="text-[15px] font-bold">Módulos del vehículo</h2>
          </div>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
            <ModuleRow title="Ventanas" subtitle="Control de ventanas" icon="maximize" />
            <ModuleRow title="Iluminación" subtitle="Luces exteriores" icon="sun" />
            <ModuleRow title="Seguros" subtitle="Cierre centralizado" icon="lock" />
          </div>
        </section>
      </div>
    </ScreenFrame>
  );
}
