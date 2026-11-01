import Link from 'next/link';
import { AlertCircle, Bluetooth, CalendarDays, ChevronRight, Cpu, Info, Navigation } from 'lucide-react';
import { InstallationGuide } from '@/components/installation-guide';
import { PlatformInformation } from '@/components/platform-information';
import { InfoRow, PageTitle, ScreenFrame } from '@/components/pichu-ui';

export default function SettingsPage() {
  return (
    <ScreenFrame>
      <PageTitle
        eyebrow="PREFERENCIAS"
        title="Configuración"
        subtitle="Información de la aplicación y del vehículo."
      />

      <section className="rounded-2xl border border-border bg-card px-[15px]">
        <InfoRow icon={Navigation} label="Vehículo" value="Mazda 3 Sedan" />
        <InfoRow icon={CalendarDays} label="Modelo" value="2011" />
        <InfoRow icon={Bluetooth} label="Conexión" value="No conectada" />
        <InfoRow icon={Cpu} label="Modo" value="Vista local" />
        <PlatformInformation />
        <InfoRow icon={Info} label="Versión" value="1.0.0" last />
      </section>

      <div className="flex items-start gap-[11px] rounded-[14px] border border-border bg-card p-[15px]">
        <AlertCircle aria-hidden="true" size={18} className="mt-0.5 shrink-0 text-gold" />
        <p className="text-xs leading-[18px] text-muted-foreground">
          La conexión con el vehículo aún no está configurada. Los cambios de estado del sunroof se
          muestran únicamente en esta aplicación.
        </p>
      </div>

      <InstallationGuide />

      <Link
        href="/vehicle/"
        className="flex min-h-[58px] items-center justify-between rounded-[14px] border border-border bg-card px-[15px] transition-opacity hover:opacity-80"
      >
        <span className="text-[13px] font-semibold">Ver módulos del vehículo</span>
        <ChevronRight aria-hidden="true" size={18} className="text-gold" />
      </Link>
    </ScreenFrame>
  );
}
