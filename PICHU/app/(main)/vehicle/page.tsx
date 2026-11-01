import { CarStage, ModuleRow, PageTitle, ScreenFrame } from '@/components/pichu-ui';

export default function VehiclePage() {
  return (
    <ScreenFrame>
      <PageTitle
        eyebrow="VISTA INTERACTIVA"
        title="Tu Mazda 3"
        subtitle="Selecciona el punto sobre el techo para abrir su control."
      />
      <div className="grid gap-5 lg:grid-cols-[minmax(0,1.3fr)_minmax(300px,0.8fr)] lg:items-start lg:gap-7">
        <CarStage />
        <section className="flex flex-col gap-3">
          <h2 className="text-[15px] font-bold">Componentes</h2>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-1">
            <ModuleRow
              title="Sunroof"
              subtitle="Control disponible · vista local"
              icon="sun"
              href="/sunroof/"
            />
            <ModuleRow title="Ventanas" subtitle="Módulo aún no disponible" icon="maximize" />
            <ModuleRow title="Iluminación" subtitle="Módulo aún no disponible" icon="sun" />
            <ModuleRow title="Seguros y sensores" subtitle="Módulos aún no disponibles" icon="lock" />
          </div>
        </section>
      </div>
    </ScreenFrame>
  );
}
