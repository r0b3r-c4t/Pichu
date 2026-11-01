import { Bluetooth } from 'lucide-react';
import { ModuleRow, PageTitle, ScreenFrame } from '@/components/pichu-ui';

export default function DevicesPage() {
  return (
    <ScreenFrame>
      <PageTitle
        eyebrow="CONTROL DEL VEHÍCULO"
        title="Dispositivos"
        subtitle="Consulta las funciones disponibles para tu vehículo."
      />

      <div className="grid gap-5 lg:grid-cols-[minmax(280px,0.8fr)_minmax(0,1.2fr)] lg:items-start lg:gap-7">
        <section className="flex flex-col gap-[11px] rounded-2xl border border-border bg-card p-4 sm:p-5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="text-sm font-bold">Estado Bluetooth</h2>
            <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card px-2.5 py-1.5 text-[9px] font-semibold tracking-wide text-muted-foreground">
              <Bluetooth aria-hidden="true" size={13} className="text-gold" />
              SIN CONEXIÓN
            </span>
          </div>
          <p className="text-xs leading-[18px] text-muted-foreground">
            No hay conexión con el vehículo. El control del sunroof muestra una vista local y todavía
            no envía comandos al coche.
          </p>
        </section>

        <section className="flex flex-col gap-[9px]">
          <h2 className="mb-0.5 text-sm font-bold">Mazda 3 Sedan · 2011</h2>
          <div className="grid gap-2 sm:grid-cols-2">
            <ModuleRow title="Sunroof" subtitle="Abrir, cerrar y detener" icon="sun" href="/sunroof/" />
            <ModuleRow title="Ventanas" subtitle="Próximamente" icon="maximize" />
            <ModuleRow title="Iluminación" subtitle="Próximamente" icon="sun" />
            <ModuleRow title="Seguros" subtitle="Próximamente" icon="lock" />
            <ModuleRow title="Sensores" subtitle="Próximamente" icon="radio" />
          </div>
        </section>
      </div>
    </ScreenFrame>
  );
}
